package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"p3y/agent"
	"p3y/artifacts"
	"p3y/benchmark"
	"p3y/ctf"
	"p3y/db"
	actool "github.com/Autumn-27/norma/tool"
)

type benchSessionRuntime struct {
	sessionID     int64
	prov          benchmark.Provider
	cfg           benchmark.SessionConfig
	cancel        context.CancelFunc
	cooldownUntil time.Time
	lastReclaimAt time.Time
	extraTools    []actool.CoreTool
	toolsLoaded   bool
	lastEnvPoll   map[string]time.Time
	taskStartAt   map[string]time.Time
}

// BenchmarkManager orchestrates unattended zero-touch multi-platform benchmark
// sessions (TSecBench REST, CTF2/DASCTF MCP, and Generic MCP + Skill.zip).
type BenchmarkManager struct {
	s    *Server
	mu   sync.Mutex
	runs map[int64]*benchSessionRuntime
}

func newBenchmarkManager(s *Server) *BenchmarkManager {
	return &BenchmarkManager{
		s:    s,
		runs: map[int64]*benchSessionRuntime{},
	}
}

func (s *Server) registerBenchmarkHooks() {
	if s.bench == nil {
		s.bench = newBenchmarkManager(s)
	}
	ctf.BenchmarkFlagHook = s.bench.handleFlagCandidate
	agent.BenchmarkChoiceHook = s.bench.handleChoice
	agent.BenchmarkExtraToolsHook = s.bench.extraToolsForTask
	agent.BenchmarkContextHook = s.bench.contextForTask
	go s.bench.resumeRunningSessions()
}

func (s *Server) registerBenchmarkRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/benchmarks/test-connection", s.bench.handleTestConnection)
	mux.HandleFunc("POST /api/benchmarks/parse-skill", s.bench.handleParseSkill)
	mux.HandleFunc("GET /api/benchmarks", s.bench.handleListSessions)
	mux.HandleFunc("POST /api/benchmarks", s.bench.handleCreateSession)
	mux.HandleFunc("GET /api/benchmarks/{id}", s.bench.handleGetSession)
	mux.HandleFunc("POST /api/benchmarks/{id}/start", s.bench.handleStartSession)
	mux.HandleFunc("POST /api/benchmarks/{id}/stop", s.bench.handleStopSession)
	mux.HandleFunc("POST /api/benchmarks/{id}/sync", s.bench.handleSyncSession)
	mux.HandleFunc("POST /api/benchmarks/{id}/retry-failed", s.bench.handleRetryFailed)
	mux.HandleFunc("DELETE /api/benchmarks/{id}", s.bench.handleDeleteSession)
	mux.HandleFunc("GET /api/benchmarks/{id}/export", s.bench.handleExportSession)
}

func parseSessionConfig(raw json.RawMessage) benchmark.SessionConfig {
	var cfg benchmark.SessionConfig
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &cfg)
	}
	return cfg
}

func (bm *BenchmarkManager) providerFor(sess *db.BenchmarkSession) (benchmark.Provider, benchmark.SessionConfig, error) {
	cfg := parseSessionConfig(sess.Config)
	prov, err := benchmark.NewProvider(sess.Provider, sess.BaseURL, sess.Token, cfg)
	if err != nil {
		return nil, cfg, err
	}
	return prov, cfg, nil
}

func (bm *BenchmarkManager) runtimeFor(sess *db.BenchmarkSession) (*benchSessionRuntime, error) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	if rt, ok := bm.runs[sess.ID]; ok && rt != nil {
		return rt, nil
	}
	prov, cfg, err := bm.providerFor(sess)
	if err != nil {
		return nil, err
	}
	rt := &benchSessionRuntime{
		sessionID:   sess.ID,
		prov:        prov,
		cfg:         cfg,
		lastEnvPoll: map[string]time.Time{},
		taskStartAt: map[string]time.Time{},
	}
	bm.runs[sess.ID] = rt
	return rt, nil
}

// ---- HTTP Handlers ----

type benchmarkCreatePayload struct {
	Name                string                  `json:"name"`
	Provider            string                  `json:"provider"`
	BaseURL             string                  `json:"base_url"`
	Token               string                  `json:"token"`
	Config              benchmark.SessionConfig `json:"config"`
	MaxConcurrent       int                     `json:"max_concurrent"`
	HintPolicy          string                  `json:"hint_policy"`
	PerChallengeTimeout int                     `json:"per_challenge_timeout"`
	LLMProfileIDs       []int64                 `json:"llm_profile_ids"`
	AutoStart           bool                    `json:"auto_start"`
}

func (bm *BenchmarkManager) handleTestConnection(w http.ResponseWriter, r *http.Request) {
	var req benchmarkCreatePayload
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&req); err != nil {
		writeErr(w, 400, "请求格式无效")
		return
	}
	prov, err := benchmark.NewProvider(req.Provider, req.BaseURL, req.Token, req.Config)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	profile, whoErr := prov.WhoAmI(ctx)
	challenges, listErr := prov.ListChallenges(ctx, req.Config)
	var discovered []string
	if gc, ok := prov.(*benchmark.GenericMCPClient); ok {
		if tools, derr := gc.DiscoverSafeTools(ctx); derr == nil {
			for _, tl := range tools {
				discovered = append(discovered, tl.Name())
			}
		}
	}
	if listErr != nil && whoErr != nil {
		writeErr(w, 502, listErr.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"ok":               listErr == nil,
		"provider":         prov.Kind(),
		"profile":          profile,
		"challenge_count":  len(challenges),
		"discovered_tools": discovered,
		"error":            errString(listErr),
	})
}

func (bm *BenchmarkManager) handleParseSkill(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(20 << 20); err != nil {
		writeErr(w, 400, "上传表单无效："+err.Error())
		return
	}
	f, _, err := r.FormFile("file")
	if err != nil {
		writeErr(w, 400, "缺少 file 上传字段")
		return
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, (16<<20)+1))
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	pkg, err := benchmark.ParseSkillZip(raw)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, pkg)
}

func (bm *BenchmarkManager) handleListSessions(w http.ResponseWriter, r *http.Request) {
	list, err := bm.s.m.pg.ListBenchmarkSessions(r.Context())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	_ = bm.s.m.pg.PopulateBenchmarkSessionTokens(r.Context(), list)
	writeJSON(w, 200, list)
}

func (bm *BenchmarkManager) handleCreateSession(w http.ResponseWriter, r *http.Request) {
	var req benchmarkCreatePayload
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.Contains(ct, "multipart/form-data") {
		if err := r.ParseMultipartForm(20 << 20); err != nil {
			writeErr(w, 400, "表单解析失败："+err.Error())
			return
		}
		meta := r.FormValue("payload")
		if strings.TrimSpace(meta) == "" {
			writeErr(w, 400, "缺少 payload 字段")
			return
		}
		if err := json.Unmarshal([]byte(meta), &req); err != nil {
			writeErr(w, 400, "payload JSON 无效")
			return
		}
		if f, _, err := r.FormFile("skill_zip"); err == nil {
			defer f.Close()
			raw, _ := io.ReadAll(io.LimitReader(f, (16<<20)+1))
			if pkg, perr := benchmark.ParseSkillZip(raw); perr == nil {
				req.Config.SkillName = pkg.Name
				req.Config.SkillInstructions = pkg.Instructions
			} else {
				writeErr(w, 400, perr.Error())
				return
			}
		}
	} else {
		if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&req); err != nil {
			writeErr(w, 400, "JSON 格式无效")
			return
		}
	}
	if strings.TrimSpace(req.Name) == "" {
		req.Name = fmt.Sprintf("测评会话 %s", time.Now().Format("01-02 15:04"))
	}
	if _, err := benchmark.NewProvider(req.Provider, req.BaseURL, req.Token, req.Config); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	cfgRaw, _ := json.Marshal(req.Config)
	sess, err := bm.s.m.pg.CreateBenchmarkSession(r.Context(), db.BenchmarkSessionCreate{
		Name:                req.Name,
		Provider:            req.Provider,
		BaseURL:             req.BaseURL,
		Token:               req.Token,
		Config:              cfgRaw,
		MaxConcurrent:       req.MaxConcurrent,
		HintPolicy:          req.HintPolicy,
		PerChallengeTimeout: req.PerChallengeTimeout,
		LLMProfileIDs:       req.LLMProfileIDs,
	})
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	_ = bm.s.m.pg.AppendBenchmarkEvent(r.Context(), sess.ID, "", "session_created",
		fmt.Sprintf("已创建测评会话（平台：%s）", sess.Provider), nil)

	// Best-effort initial sync so UI shows challenge matrix immediately.
	syncCtx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	if _, serr := bm.syncChallenges(syncCtx, sess); serr != nil {
		_ = bm.s.m.pg.AppendBenchmarkEvent(r.Context(), sess.ID, "", "sync_warn", "初始题库同步失败："+serr.Error(), nil)
	}
	cancel()

	if req.AutoStart {
		_ = bm.startSession(sess.ID)
	}
	updated, err := bm.s.m.pg.GetBenchmarkSession(r.Context(), sess.ID)
	if err == nil && updated != nil {
		sess = updated
	}
	writeJSON(w, 201, sess)
}

func (bm *BenchmarkManager) handleGetSession(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "无效的测评会话 ID")
		return
	}
	sess, err := bm.s.m.pg.GetBenchmarkSession(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if sess == nil {
		writeErr(w, 404, "测评会话不存在")
		return
	}
	challenges, err := bm.s.m.pg.ListBenchmarkChallenges(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	_ = bm.s.m.pg.PopulateBenchmarkSessionTokens(r.Context(), []*db.BenchmarkSession{sess})
	_ = bm.s.m.pg.PopulateBenchmarkChallengeTokens(r.Context(), id, challenges)
	submissions, _ := bm.s.m.pg.ListBenchmarkSubmissions(r.Context(), id)
	events, _ := bm.s.m.pg.ListBenchmarkEvents(r.Context(), id, 150)
	writeJSON(w, 200, map[string]any{
		"session":     sess,
		"challenges":  challenges,
		"submissions": submissions,
		"events":      events,
	})
}

func (bm *BenchmarkManager) handleStartSession(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "无效的测评会话 ID")
		return
	}
	if err := bm.startSession(id); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	sess, _ := bm.s.m.pg.GetBenchmarkSession(r.Context(), id)
	writeJSON(w, 200, sess)
}

func (bm *BenchmarkManager) handleStopSession(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "无效的测评会话 ID")
		return
	}
	bm.stopSession(id, "stopped", "用户手动停止测评")
	sess, _ := bm.s.m.pg.GetBenchmarkSession(r.Context(), id)
	writeJSON(w, 200, sess)
}

func (bm *BenchmarkManager) handleSyncSession(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "无效的测评会话 ID")
		return
	}
	sess, err := bm.s.m.pg.GetBenchmarkSession(r.Context(), id)
	if err != nil || sess == nil {
		writeErr(w, 404, "测评会话不存在")
		return
	}
	n, err := bm.syncChallenges(r.Context(), sess)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	_ = bm.s.m.pg.ClearBenchmarkTransientErrors(r.Context(), id)
	sess, _ = bm.s.m.pg.GetBenchmarkSession(r.Context(), id)
	writeJSON(w, 200, map[string]any{"synced": n, "session": sess})
}

func (bm *BenchmarkManager) handleRetryFailed(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "无效的测评会话 ID")
		return
	}
	sess, err := bm.s.m.pg.GetBenchmarkSession(r.Context(), id)
	if err != nil || sess == nil {
		writeErr(w, 404, "测评会话不存在")
		return
	}
	resetCount, err := bm.s.m.pg.ResetFailedBenchmarkChallenges(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if resetCount > 0 {
		_ = bm.s.m.pg.AppendBenchmarkEvent(r.Context(), id, "", "retry_queued",
			fmt.Sprintf("已将 %d 道中断/失败题目重置回优先待调度队列", resetCount), nil)
	}
	sess, _ = bm.s.m.pg.GetBenchmarkSession(r.Context(), id)
	writeJSON(w, 200, map[string]any{"reset": resetCount, "session": sess})
}

func (bm *BenchmarkManager) resumeRunningSessions() {
	if bm == nil || bm.s == nil || bm.s.m == nil || bm.s.m.pg == nil || bm.s.ctx == nil {
		return
	}
	sessions, err := bm.s.m.pg.ListBenchmarkSessions(bm.s.ctx)
	if err != nil {
		return
	}
	for _, sess := range sessions {
		if sess != nil && sess.Status == "running" {
			_ = bm.startSession(sess.ID)
		}
	}
}

func (bm *BenchmarkManager) handleDeleteSession(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "无效的测评会话 ID")
		return
	}
	bm.stopSession(id, "stopped", "删除测评会话")
	taskIDs, _ := bm.s.m.pg.ListBenchmarkChallengeTaskIDs(r.Context(), id)
	for _, tid := range taskIDs {
		tidStr := strconv.FormatInt(tid, 10)
		bm.s.engine.StopTask(tidStr)
		_, _ = bm.s.m.DeleteTask(tidStr, DeleteTaskOptions{})
	}
	bm.mu.Lock()
	delete(bm.runs, id)
	bm.mu.Unlock()
	if err := bm.s.m.pg.DeleteBenchmarkSession(r.Context(), id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": true, "id": id})
}

func (bm *BenchmarkManager) handleExportSession(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "无效的测评会话 ID")
		return
	}
	sess, err := bm.s.m.pg.GetBenchmarkSession(r.Context(), id)
	if err != nil || sess == nil {
		writeErr(w, 404, "测评会话不存在")
		return
	}
	challenges, _ := bm.s.m.pg.ListBenchmarkChallenges(r.Context(), id)
	_ = bm.s.m.pg.PopulateBenchmarkSessionTokens(r.Context(), []*db.BenchmarkSession{sess})
	_ = bm.s.m.pg.PopulateBenchmarkChallengeTokens(r.Context(), id, challenges)
	submissions, _ := bm.s.m.pg.ListBenchmarkSubmissions(r.Context(), id)
	events, _ := bm.s.m.pg.ListBenchmarkEvents(r.Context(), id, 500)
	payload := map[string]any{
		"exported_at": time.Now().UTC(),
		"session":     sess,
		"challenges":  challenges,
		"submissions": submissions,
		"events":      events,
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="benchmark-%d.json"`, id))
	writeJSON(w, 200, payload)
}

// ---- Orchestration ----

func (bm *BenchmarkManager) syncChallenges(ctx context.Context, sess *db.BenchmarkSession) (int, error) {
	rt, err := bm.runtimeFor(sess)
	if err != nil {
		return 0, err
	}
	specs, err := rt.prov.ListChallenges(ctx, rt.cfg)
	if err != nil {
		return 0, err
	}
	upserts := make([]db.BenchmarkChallengeUpsert, 0, len(specs))
	for _, c := range specs {
		upserts = append(upserts, db.BenchmarkChallengeUpsert{
			UniqueCode:       c.UniqueCode,
			Title:            c.Title,
			Description:      c.Description,
			Category:         c.Category,
			Difficulty:       c.Difficulty,
			Level:            c.Level,
			SubmissionType:   c.SubmissionType,
			TotalScore:       c.TotalScore,
			CumulativeScore:  c.CumulativeScore,
			FlagCount:        c.FlagCount,
			CorrectFlagCount: c.CorrectFlagCount,
			IsCompleted:      c.IsCompleted,
			ContainerStatus:  c.ContainerStatus,
			ContainerAddr:    c.ContainerAddr,
			Meta:             benchmark.ChallengeMetaJSON(c),
		})
	}
	if err := bm.s.m.pg.SyncBenchmarkChallenges(ctx, sess.ID, upserts); err != nil {
		return 0, err
	}
	return len(upserts), nil
}

func (bm *BenchmarkManager) startSession(sessionID int64) error {
	sess, err := bm.s.m.pg.GetBenchmarkSession(context.Background(), sessionID)
	if err != nil {
		return err
	}
	if sess == nil {
		return errors.New("测评会话不存在")
	}
	rt, err := bm.runtimeFor(sess)
	if err != nil {
		return err
	}
	bm.mu.Lock()
	if rt.cancel != nil {
		rt.cancel()
	}
	ctx, cancel := context.WithCancel(bm.s.ctx)
	rt.cancel = cancel
	bm.mu.Unlock()

	if err := bm.s.m.pg.UpdateBenchmarkSessionStatus(context.Background(), sessionID, "running", ""); err != nil {
		cancel()
		return err
	}
	_ = bm.s.m.pg.AppendBenchmarkEvent(context.Background(), sessionID, "", "session_started", "开始零交互自动测评", nil)
	go bm.runSessionLoop(ctx, sessionID, rt)
	return nil
}

func (bm *BenchmarkManager) stopSession(sessionID int64, terminalStatus, reason string) {
	bm.mu.Lock()
	rt := bm.runs[sessionID]
	if rt != nil && rt.cancel != nil {
		rt.cancel()
		rt.cancel = nil
	}
	bm.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	sess, _ := bm.s.m.pg.GetBenchmarkSession(ctx, sessionID)
	if sess != nil {
		if rt == nil {
			rt, _ = bm.runtimeFor(sess)
		}
		if rt != nil {
			challenges, _ := bm.s.m.pg.ListBenchmarkChallenges(ctx, sessionID)
			for _, ch := range challenges {
				if ch.ContainerStatus == "available" || ch.ContainerStatus == "pending" {
					_ = rt.prov.CloseEnvironment(ctx, ch.UniqueCode)
					_ = bm.s.m.pg.UpdateBenchmarkChallengeEnv(ctx, sessionID, ch.UniqueCode, "stopped", nil, nil, "")
				}
				if ch.BoundTaskID != nil {
					taskID := strconv.FormatInt(*ch.BoundTaskID, 10)
					wasRunning := false
					if t, ok := bm.s.m.Task(taskID); ok && !isTerminalStatus(t.lifecycleSnapshot().Status) {
						wasRunning = true
					}
					bm.stopBoundTask(taskID, "failed", errors.New(reason))
					if wasRunning && !ch.IsCompleted {
						_ = bm.s.m.pg.ResetBenchmarkChallengeForRetry(ctx, sessionID, ch.UniqueCode)
					}
				}
			}
		}
		_ = bm.s.m.pg.UpdateBenchmarkSessionStatus(ctx, sessionID, terminalStatus, "")
		_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sessionID, "", "session_stopped", reason, nil)
	}
}

func (bm *BenchmarkManager) stopBoundTask(taskID, terminalStatus string, cause error) {
	if t, ok := bm.s.m.Task(taskID); ok {
		if !isTerminalStatus(t.lifecycleSnapshot().Status) {
			_ = bm.s.m.SetTaskStatus(taskID, terminalStatus)
		}
		bm.s.engine.cancelExec(taskID, cause)
		t.Notify()
	}
}

func (bm *BenchmarkManager) runSessionLoop(ctx context.Context, sessionID int64, rt *benchSessionRuntime) {
	sess, err := bm.s.m.pg.GetBenchmarkSession(ctx, sessionID)
	if err != nil || sess == nil {
		return
	}
	effectiveSlots := sess.MaxConcurrent
	activeRemoteEnvs := 0
	if prof, werr := rt.prov.WhoAmI(ctx); werr == nil && prof != nil {
		if prof.MaxEnvironments > 0 && prof.MaxEnvironments < effectiveSlots {
			effectiveSlots = prof.MaxEnvironments
		}
		activeRemoteEnvs = prof.ActiveEnvironments
		_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sessionID, "", "whoami",
			fmt.Sprintf("平台凭证校验成功（并发环境配额=%d，平台当前占用=%d）", prof.MaxEnvironments, prof.ActiveEnvironments), prof)
	} else if werr != nil {
		_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sessionID, "", "whoami_warn", "获取平台配额信息失败："+werr.Error(), nil)
	}
	_ = bm.s.m.pg.ClearBenchmarkTransientErrors(ctx, sessionID)
	if _, serr := bm.syncChallenges(ctx, sess); serr != nil {
		_ = bm.s.m.pg.UpdateBenchmarkSessionStatus(context.Background(), sessionID, "failed", serr.Error())
		_ = bm.s.m.pg.AppendBenchmarkEvent(context.Background(), sessionID, "", "error", "同步题目列表失败："+serr.Error(), nil)
		return
	}
	if activeRemoteEnvs > 0 {
		if existing, lerr := bm.s.m.pg.ListBenchmarkChallenges(ctx, sessionID); lerr == nil {
			bm.reclaimOrphanedEnvironments(ctx, rt, sess, existing)
		}
	}

	ticker := time.NewTicker(4 * time.Second)
	defer ticker.Stop()

	for {
		if err := bm.tickSession(ctx, sessionID, rt, effectiveSlots); err != nil {
			if ctx.Err() != nil {
				return
			}
			var se *benchmark.StructuredError
			if errors.As(err, &se) && (se.HTTPStatus == 401 || se.Code == "ENDED" || se.Code == "EXPIRED") {
				_ = bm.s.m.pg.UpdateBenchmarkSessionStatus(context.Background(), sessionID, "expired", err.Error())
				_ = bm.s.m.pg.AppendBenchmarkEvent(context.Background(), sessionID, "", "session_expired", err.Error(), nil)
				return
			}
			_ = bm.s.m.pg.AppendBenchmarkEvent(context.Background(), sessionID, "", "tick_warn", err.Error(), nil)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (bm *BenchmarkManager) tickSession(ctx context.Context, sessionID int64, rt *benchSessionRuntime, effectiveSlots int) error {
	sess, err := bm.s.m.pg.GetBenchmarkSession(ctx, sessionID)
	if err != nil || sess == nil || sess.Status != "running" {
		return context.Canceled
	}
	if effectiveSlots <= 0 {
		effectiveSlots = 1
	}
	if time.Now().Before(rt.cooldownUntil) {
		return nil
	}

	challenges, err := bm.s.m.pg.ListBenchmarkChallenges(ctx, sessionID)
	if err != nil {
		return err
	}
	unsolved := make([]*db.BenchmarkChallenge, 0, len(challenges))
	activeContainers := 0
	activeTasks := 0

	for _, ch := range challenges {
		hasContainer := ch.ContainerStatus == "available" || ch.ContainerStatus == "pending"

		var boundRunning bool
		if ch.BoundTaskID != nil {
			t, ok := bm.s.m.Task(strconv.FormatInt(*ch.BoundTaskID, 10))
			if ok && !isTerminalStatus(t.lifecycleSnapshot().Status) {
				boundRunning = true
				activeTasks++
			}
		}

		// Recover incomplete challenges that previously terminated before receiving a
		// challenge description (or had no detail synced) so they re-enter the front
		// of the queue to fetch fresh detail and container/attachments properly.
		if !ch.IsCompleted && ch.BoundTaskID != nil && !boundRunning && strings.TrimSpace(ch.Description) == "" {
			if rerr := bm.s.m.pg.ResetBenchmarkChallengeForRetry(ctx, sessionID, ch.UniqueCode); rerr == nil {
				ch.BoundTaskID = nil
				ch.BoundTaskStatus = ""
				ch.AttemptCount = 0
				ch.LastError = ""
				ch.ContainerStatus = "stopped"
				ch.ContainerAddr = nil
				hasContainer = false
			}
		}

		// Cleanup stray containers for already-solved or finished/idle challenges so
		// platform environment quota is released immediately.
		if hasContainer && (ch.IsCompleted || !boundRunning) {
			_ = rt.prov.CloseEnvironment(ctx, ch.UniqueCode)
			_ = bm.s.m.pg.UpdateBenchmarkChallengeEnv(ctx, sessionID, ch.UniqueCode, "stopped", nil, nil, "")
			hasContainer = false
		}
		if ch.IsCompleted {
			continue
		}
		unsolved = append(unsolved, ch)

		if hasContainer {
			activeContainers++
			bm.refreshActiveEnv(ctx, rt, sess, ch)
		}
		if boundRunning {
			bm.checkChallengeTimeoutAndHint(ctx, rt, sess, ch, len(unsolved) > activeTasks)
		}
	}

	if len(unsolved) == 0 {
		_ = bm.s.m.pg.UpdateBenchmarkSessionStatus(ctx, sessionID, "completed", "")
		_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sessionID, "", "session_completed",
			fmt.Sprintf("全部 %d 道题目已完成，最终得分 %d/%d", sess.TotalCount, sess.TotalScore, sess.MaxPossibleScore), nil)
		bm.mu.Lock()
		if rt.cancel != nil {
			rt.cancel()
		}
		bm.mu.Unlock()
		return context.Canceled
	}

	maxTasks := max(effectiveSlots, sess.MaxConcurrent)
	if activeTasks >= maxTasks {
		return nil
	}

	for _, ch := range pickChallengeQueue(unsolved, bm.s.m) {
		if activeTasks >= maxTasks {
			break
		}
		if challengeHasContainer(sess.Provider, ch) && activeContainers >= effectiveSlots {
			continue
		}
		launched, needsContainer, err := bm.startChallengeSlot(ctx, rt, sess, ch, effectiveSlots, activeContainers)
		if err != nil {
			if errors.Is(err, errBenchmarkQuotaDeferred) {
				continue
			}
			var se *benchmark.StructuredError
			if errors.As(err, &se) {
				if se.RetryAfterMs > 0 {
					rt.cooldownUntil = time.Now().Add(time.Duration(se.RetryAfterMs) * time.Millisecond)
				}
				if se.Code == "ENDED" || se.Code == "EXPIRED" {
					return err
				}
				if strings.EqualFold(se.Code, "agent_environment_limit") {
					// Platform container quota is currently full: do NOT stamp all queued
					// container challenges red; block further container launches this tick
					// and probe/reclaim any leaked container from earlier runs.
					activeContainers = effectiveSlots
					reclaimed := bm.reclaimOrphanedEnvironments(ctx, rt, sess, challenges)
					if reclaimed == 0 {
						_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sessionID, ch.UniqueCode, "env_limit_wait",
							"平台并发容器配额已满，等待空位或回收残留容器后再调度需要靶机的题目", nil)
					}
					continue
				}
			}
			if cooldown, reason := isTransientPlatformUnavailableError(err); cooldown > 0 {
				if cooldown > time.Until(rt.cooldownUntil) {
					rt.cooldownUntil = time.Now().Add(cooldown)
				}
				_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sessionID, ch.UniqueCode, "platform_cooldown",
					fmt.Sprintf("%s（冷却 %ds）：%v", reason, int(cooldown.Seconds()), err), nil)
				break
			}
			_ = bm.s.m.pg.UpdateBenchmarkChallengeEnv(ctx, sessionID, ch.UniqueCode, ch.ContainerStatus, ch.ContainerAddr, ch.EnvExpiresAt, err.Error())
			_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sessionID, ch.UniqueCode, "slot_error", err.Error(), nil)
			continue
		}
		if launched {
			activeTasks++
			if needsContainer {
				activeContainers++
			}
		}
	}
	return nil
}

// reclaimOrphanedEnvironments probes candidate challenges on the platform when
// remote environment quota appears full, closing leaked containers whose P3Y task
// is absent or terminal and adopting legitimately running containers into DB state.
func (bm *BenchmarkManager) reclaimOrphanedEnvironments(ctx context.Context, rt *benchSessionRuntime, sess *db.BenchmarkSession, challenges []*db.BenchmarkChallenge) int {
	bm.mu.Lock()
	if time.Since(rt.lastReclaimAt) < 20*time.Second {
		bm.mu.Unlock()
		return 0
	}
	rt.lastReclaimAt = time.Now()
	bm.mu.Unlock()

	candidates := make([]*db.BenchmarkChallenge, 0, 16)
	fallback := make([]*db.BenchmarkChallenge, 0, 24)
	for _, ch := range challenges {
		if ch.ContainerStatus == "available" || ch.ContainerStatus == "pending" || ch.AttemptCount > 0 || ch.BoundTaskID != nil {
			candidates = append(candidates, ch)
		} else if challengeHasContainer(sess.Provider, ch) && len(fallback) < 20 {
			fallback = append(fallback, ch)
		}
	}
	candidates = append(candidates, fallback...)

	reclaimed := 0
	for _, ch := range candidates {
		if ctx.Err() != nil {
			break
		}
		env, err := rt.prov.GetEnvironment(ctx, ch.UniqueCode)
		if err != nil || env == nil {
			continue
		}
		if env.Status != "available" && env.Status != "pending" && len(env.Addrs) == 0 {
			continue
		}
		var boundRunning bool
		if ch.BoundTaskID != nil {
			if t, ok := bm.s.m.Task(strconv.FormatInt(*ch.BoundTaskID, 10)); ok && !isTerminalStatus(t.lifecycleSnapshot().Status) {
				boundRunning = true
			}
		}
		if boundRunning {
			_ = bm.s.m.pg.UpdateBenchmarkChallengeEnv(ctx, sess.ID, ch.UniqueCode, env.Status, env.Addrs, env.ExpiresAt, "")
			continue
		}
		if cerr := rt.prov.CloseEnvironment(ctx, ch.UniqueCode); cerr == nil {
			reclaimed++
			_ = bm.s.m.pg.UpdateBenchmarkChallengeEnv(ctx, sess.ID, ch.UniqueCode, "stopped", nil, nil, "")
			_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sess.ID, ch.UniqueCode, "env_reclaimed",
				fmt.Sprintf("已自动回收平台残留靶机容器（%s）释放并发配额", ch.Title), nil)
		}
	}
	if reclaimed > 0 {
		_ = bm.s.m.pg.ClearBenchmarkQuotaErrors(ctx, sess.ID)
	}
	return reclaimed
}

func (bm *BenchmarkManager) refreshActiveEnv(ctx context.Context, rt *benchSessionRuntime, sess *db.BenchmarkSession, ch *db.BenchmarkChallenge) {
	bm.mu.Lock()
	last := rt.lastEnvPoll[ch.UniqueCode]
	if time.Since(last) < 15*time.Second {
		bm.mu.Unlock()
		return
	}
	rt.lastEnvPoll[ch.UniqueCode] = time.Now()
	bm.mu.Unlock()

	env, err := rt.prov.GetEnvironment(ctx, ch.UniqueCode)
	if err != nil || env == nil {
		return
	}
	var exp *time.Time
	if env.ExpiresAt != nil {
		exp = env.ExpiresAt
	} else if env.RemainingSeconds > 0 {
		t := time.Now().Add(time.Duration(env.RemainingSeconds) * time.Second)
		exp = &t
	}
	_ = bm.s.m.pg.UpdateBenchmarkChallengeEnv(ctx, sess.ID, ch.UniqueCode, env.Status, env.Addrs, exp, "")

	if env.Status == "available" && env.RemainingSeconds > 0 && env.RemainingSeconds < 300 {
		if ext, eerr := rt.prov.ExtendEnvironment(ctx, ch.UniqueCode); eerr == nil && ext != nil {
			_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sess.ID, ch.UniqueCode, "env_extended",
				fmt.Sprintf("靶机容器 %s 剩余不足 5 分钟，已自动续期", ch.UniqueCode), ext)
		}
	}
}

func (bm *BenchmarkManager) checkChallengeTimeoutAndHint(ctx context.Context, rt *benchSessionRuntime, sess *db.BenchmarkSession, ch *db.BenchmarkChallenge, hasWaiting bool) {
	if ch.BoundTaskID == nil {
		return
	}
	bm.mu.Lock()
	started := rt.taskStartAt[ch.UniqueCode]
	if started.IsZero() {
		started = ch.UpdatedAt
		rt.taskStartAt[ch.UniqueCode] = started
	}
	bm.mu.Unlock()

	elapsed := time.Since(started)
	timeout := time.Duration(sess.PerChallengeTimeout) * time.Second
	if sess.HintPolicy == "stagnant_only" && !ch.HintUsed && timeout > 0 && elapsed > timeout/2 {
		if hint, err := rt.prov.GetHint(ctx, ch.UniqueCode); err == nil && strings.TrimSpace(hint) != "" {
			_ = bm.s.m.pg.SaveBenchmarkChallengeHint(ctx, sess.ID, ch.UniqueCode, hint)
			_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sess.ID, ch.UniqueCode, "hint_fetched", "停滞自动获取题目 Hint", map[string]any{"hint": hint})
			if t, ok := bm.s.m.Task(strconv.FormatInt(*ch.BoundTaskID, 10)); ok {
				_, _ = t.Store.AddNode("fact", map[string]any{
					"summary": "【平台 Hint 提示】" + hint,
					"subtype": "benchmark_hint",
				}, 0, "confirmed", "benchmark", nil)
				t.Notify()
			}
		}
	}
	if timeout > 0 && elapsed > timeout && hasWaiting {
		taskID := strconv.FormatInt(*ch.BoundTaskID, 10)
		bm.stopBoundTask(taskID, "timeout", errors.New("单题预算超时，让出并发槽位"))
		if ch.ContainerStatus == "available" || ch.ContainerStatus == "pending" {
			_ = rt.prov.CloseEnvironment(ctx, ch.UniqueCode)
			_ = bm.s.m.pg.UpdateBenchmarkChallengeEnv(ctx, sess.ID, ch.UniqueCode, "stopped", nil, nil, "超时让出槽位")
		}
		_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sess.ID, ch.UniqueCode, "challenge_timeout_rotate",
			fmt.Sprintf("题目 %s 超过单题时间预算（%ds），已释放槽位调度后续题目", ch.UniqueCode, sess.PerChallengeTimeout), nil)
	}
}

func challengeHasContainer(provider string, ch *db.BenchmarkChallenge) bool {
	if ch.SubmissionType == "choice" {
		return false
	}
	var meta struct {
		HasContainer bool `json:"has_container"`
	}
	if len(ch.Meta) > 0 && json.Unmarshal(ch.Meta, &meta) == nil {
		if meta.HasContainer {
			return true
		}
	}
	return strings.EqualFold(provider, "tsecbench") && len(ch.ContainerAddr) > 0
}

func isNoFlagBenchmarkChallenge(ch *db.BenchmarkChallenge) bool {
	if ch == nil {
		return false
	}
	title := strings.ToLower(ch.Title)
	desc := strings.ToLower(ch.Description)
	return strings.Contains(title, "[无flag]") || strings.Contains(desc, "本题无flag")
}

func isTransientPlatformUnavailableError(err error) (time.Duration, string) {
	if err == nil {
		return 0, ""
	}
	var se *benchmark.StructuredError
	if errors.As(err, &se) {
		code := strings.ToLower(strings.TrimSpace(se.Code))
		if code == "maintenance_mode" || strings.Contains(strings.ToLower(se.Message), "maintenance") {
			wait := 30 * time.Second
			if se.RetryAfterMs > 0 {
				wait = max(wait, time.Duration(se.RetryAfterMs)*time.Millisecond)
			}
			return wait, "平台处于系统维护状态"
		}
		if se.HTTPStatus == 429 || strings.Contains(code, "rate_limit") {
			wait := 15 * time.Second
			if se.RetryAfterMs > 0 {
				wait = max(wait, time.Duration(se.RetryAfterMs)*time.Millisecond)
			}
			return wait, "触发平台限流配额"
		}
		if se.HTTPStatus >= 500 || se.Retryable {
			return 20 * time.Second, "平台服务暂时不可用"
		}
	}
	lower := strings.ToLower(err.Error())
	for _, needle := range []string{
		"server misbehaving",
		"dial tcp",
		"connection reset",
		"connection refused",
		"stream error",
		"eof",
		"tls:",
		"context deadline exceeded",
		"i/o timeout",
	} {
		if strings.Contains(lower, needle) {
			return 15 * time.Second, "平台网络或连接瞬时异常"
		}
	}
	return 0, ""
}

func pickChallengeQueue(unsolved []*db.BenchmarkChallenge, m *Manager) []*db.BenchmarkChallenge {
	idle := make([]*db.BenchmarkChallenge, 0, len(unsolved))
	for _, ch := range unsolved {
		if isNoFlagBenchmarkChallenge(ch) {
			continue
		}
		if ch.BoundTaskID != nil {
			if t, ok := m.Task(strconv.FormatInt(*ch.BoundTaskID, 10)); ok && !isTerminalStatus(t.lifecycleSnapshot().Status) {
				continue
			}
		}
		if ch.AttemptCount > 0 && ch.LastError != "" {
			// Still allow retry only if all fresh ones are exhausted; order after fresh ones.
		}
		idle = append(idle, ch)
	}
	sort.SliceStable(idle, func(i, j int) bool {
		if idle[i].AttemptCount != idle[j].AttemptCount {
			return idle[i].AttemptCount < idle[j].AttemptCount
		}
		if idle[i].Level != idle[j].Level {
			return idle[i].Level < idle[j].Level
		}
		return idle[i].ID < idle[j].ID
	})
	return idle
}

var errBenchmarkQuotaDeferred = errors.New("container slot quota full")

func (bm *BenchmarkManager) startChallengeSlot(ctx context.Context, rt *benchSessionRuntime, sess *db.BenchmarkSession, ch *db.BenchmarkChallenge, effectiveSlots, activeContainers int) (launched bool, needsContainer bool, err error) {
	// 1. Always fetch fresh challenge detail first so description, category,
	//    has_container, and attachments are accurate before reserving container slots.
	detail, derr := rt.prov.GetChallengeDetail(ctx, ch.UniqueCode)
	if derr != nil {
		return false, false, fmt.Errorf("拉取题目详情失败: %w", derr)
	}
	if detail != nil {
		_ = bm.s.m.pg.SyncBenchmarkChallenges(ctx, sess.ID, []db.BenchmarkChallengeUpsert{{
			UniqueCode:       ch.UniqueCode,
			Title:            detail.Title,
			Description:      detail.Description,
			Category:         detail.Category,
			Difficulty:       detail.Difficulty,
			Level:            detail.Level,
			SubmissionType:   detail.SubmissionType,
			TotalScore:       detail.TotalScore,
			CumulativeScore:  detail.CumulativeScore,
			FlagCount:        detail.FlagCount,
			CorrectFlagCount: detail.CorrectFlagCount,
			IsCompleted:      detail.IsCompleted,
			ContainerStatus:  ch.ContainerStatus,
			ContainerAddr:    ch.ContainerAddr,
			Meta:             benchmark.ChallengeMetaJSON(*detail),
		}})
		if reloaded, rerr := bm.s.m.pg.GetBenchmarkChallenge(ctx, sess.ID, ch.UniqueCode); rerr == nil && reloaded != nil {
			ch = reloaded
		}
		if ch.LastError != "" {
			_ = bm.s.m.pg.UpdateBenchmarkChallengeEnv(ctx, sess.ID, ch.UniqueCode, ch.ContainerStatus, ch.ContainerAddr, ch.EnvExpiresAt, "")
			ch.LastError = ""
		}
		if isNoFlagBenchmarkChallenge(ch) {
			_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sess.ID, ch.UniqueCode, "challenge_skipped_no_flag",
				fmt.Sprintf("题目 %s 声明无 Flag，自动跳过调度", ch.Title), nil)
			return false, false, nil
		}
		if detail.IsCompleted {
			_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sess.ID, ch.UniqueCode, "challenge_already_solved",
				fmt.Sprintf("题目 %s 在平台端已处于完成状态，自动跳过启动", ch.Title), nil)
			return false, false, nil
		}
	}

	needsContainer = (detail != nil && detail.HasContainer) || challengeHasContainer(sess.Provider, ch)
	if needsContainer && activeContainers >= effectiveSlots {
		return false, true, errBenchmarkQuotaDeferred
	}

	var env *benchmark.EnvState
	if needsContainer {
		st, serr := rt.prov.StartEnvironment(ctx, ch.UniqueCode)
		if serr != nil {
			return false, true, serr
		}
		env = st
		// Persist initial env state immediately (e.g. pending) so UI updates live during startup poll.
		if env != nil {
			_ = bm.s.m.pg.UpdateBenchmarkChallengeEnv(ctx, sess.ID, ch.UniqueCode, env.Status, env.Addrs, env.ExpiresAt, "")
			ch.ContainerStatus = env.Status
			ch.ContainerAddr = env.Addrs
			ch.EnvExpiresAt = env.ExpiresAt
		}
		// Poll until environment becomes available with endpoints (repeating
		// idempotent start periodically when platform keeps returning pending).
		lastStartAt := time.Now()
		for deadline := time.Now().Add(45 * time.Second); env != nil && env.Status == "pending" && time.Now().Before(deadline); {
			select {
			case <-ctx.Done():
				return false, true, ctx.Err()
			case <-time.After(2 * time.Second):
			}
			if next, gerr := rt.prov.GetEnvironment(ctx, ch.UniqueCode); gerr == nil && next != nil {
				env = next
			} else if time.Since(lastStartAt) >= 10*time.Second {
				if retrySt, rerr := rt.prov.StartEnvironment(ctx, ch.UniqueCode); rerr == nil && retrySt != nil {
					env = retrySt
				}
				lastStartAt = time.Now()
			}
		}
		var exp *time.Time
		if env != nil {
			if env.ExpiresAt != nil {
				exp = env.ExpiresAt
			} else if env.RemainingSeconds > 0 {
				t := time.Now().Add(time.Duration(env.RemainingSeconds) * time.Second)
				exp = &t
			}
			_ = bm.s.m.pg.UpdateBenchmarkChallengeEnv(ctx, sess.ID, ch.UniqueCode, env.Status, env.Addrs, exp, "")
			ch.ContainerStatus = env.Status
			ch.ContainerAddr = env.Addrs
			ch.EnvExpiresAt = exp
		}
		if env == nil || len(env.Addrs) == 0 || env.Status == "failed" || env.Status == "stopped" {
			_ = rt.prov.CloseEnvironment(ctx, ch.UniqueCode)
			ch.ContainerStatus = "stopped"
			ch.ContainerAddr = nil
			return false, true, fmt.Errorf("靶机容器未就绪或未返回访问地址（status=%v）", func() string {
				if env == nil {
					return "nil"
				}
				return env.Status
			}())
		}
	}

	// Collect attachments metadata before creating goal so Planner/Worker know mounted filenames.
	var meta struct {
		Files []benchmark.AttachmentSpec `json:"files"`
	}
	if len(ch.Meta) > 0 {
		_ = json.Unmarshal(ch.Meta, &meta)
	}
	if detail != nil && len(detail.Files) > 0 {
		meta.Files = detail.Files
	}
	attachNames := make([]string, 0, len(meta.Files))
	for _, f := range meta.Files {
		if strings.TrimSpace(f.Name) != "" {
			attachNames = append(attachNames, strings.TrimSpace(f.Name))
		}
	}

	chalType := benchmark.InferChallengeType(ch.UniqueCode, ch.Category, ch.Description)
	if chalType == "auto" {
		chalType = "web"
	}
	vpnCfg, vpnHash, vpnFilename, _ := prepareTaskVPNForCreate("ctf", rt.cfg.CTFVPNConfig, rt.cfg.CTFVPNFilename)

	sid := sess.ID
	goal := buildBenchmarkChallengeGoal(ch, env, attachNames)
	desc := fmt.Sprintf("[测评#%d %s] %s", sess.ID, ch.UniqueCode, ch.Title)

	t, err := bm.s.m.CreateTaskWithOptions(desc, goal, db.TaskCreateOptions{
		Name:                 fmt.Sprintf("[%s] %s", ch.UniqueCode, ch.Title),
		Mode:                 "ctf",
		ChallengeType:        chalType,
		CTFVerifyMode:        db.CTFVerifyFlag,
		CTFVPNConfig:         vpnCfg,
		CTFVPNHash:           vpnHash,
		CTFVPNFilename:       vpnFilename,
		LLMProfileIDs:        sess.LLMProfileIDs,
		TimeoutSeconds:       sess.PerChallengeTimeout,
		PlanHeartbeatSeconds: 30,
		ZeroTouch:            true,
		BenchmarkSessionID:   &sid,
	})
	if err != nil {
		if needsContainer {
			_ = rt.prov.CloseEnvironment(ctx, ch.UniqueCode)
			_ = bm.s.m.pg.UpdateBenchmarkChallengeEnv(ctx, sess.ID, ch.UniqueCode, "stopped", nil, nil, err.Error())
		}
		return false, needsContainer, err
	}
	numericID, _ := strconv.ParseInt(t.ID, 10, 64)

	store := artifacts.Store{Root: bm.s.m.dir}
	for _, f := range meta.Files {
		fid := f.ID
		if fid == "" {
			fid = f.URL
		}
		if fid == "" {
			fid = f.Name
		}
		fname, raw, derr := rt.prov.DownloadAttachment(ctx, ch.UniqueCode, fid)
		if derr != nil || len(raw) == 0 {
			_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sess.ID, ch.UniqueCode, "attachment_warn",
				fmt.Sprintf("附件 %s 下载失败：%v", f.Name, derr), nil)
			continue
		}
		if fname == "" {
			fname = f.Name
		}
		if _, aerr := store.Add("task", t.ID, fname, "attachment", bytes.NewReader(raw)); aerr != nil {
			_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sess.ID, ch.UniqueCode, "attachment_warn",
				fmt.Sprintf("附件 %s 写入失败：%v", fname, aerr), nil)
		}
	}

	if err := bm.s.m.pg.BindBenchmarkChallengeTask(ctx, sess.ID, ch.UniqueCode, numericID); err != nil {
		return false, needsContainer, err
	}
	bm.mu.Lock()
	rt.taskStartAt[ch.UniqueCode] = time.Now()
	bm.mu.Unlock()

	bm.s.prewarmTaskVPN(t, vpnHash, vpnCfg)
	// seedFirstIntent = false: let Planner run round 1 immediately to create branch intents.
	bm.s.launchTask(t, goal, false)
	_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sess.ID, ch.UniqueCode, "challenge_started",
		fmt.Sprintf("题目已分配槽位并启动零交互求解（子任务 #%s）", t.ID), map[string]any{
			"task_id": t.ID,
			"addrs":   ch.ContainerAddr,
		})
	return true, needsContainer, nil
}

func buildBenchmarkChallengeGoal(ch *db.BenchmarkChallenge, env *benchmark.EnvState, attachNames []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "题目代号：%s\n标题：%s\n分类：%s | 难度：%s | 提交类型：%s | Flag 数：%d\n",
		ch.UniqueCode, ch.Title, ch.Category, ch.Difficulty, ch.SubmissionType, ch.FlagCount)
	addrs := ch.ContainerAddr
	if env != nil && len(env.Addrs) > 0 {
		addrs = env.Addrs
	}
	if len(addrs) > 0 {
		fmt.Fprintf(&b, "靶机访问地址：%s\n", strings.Join(addrs, ", "))
	}
	if len(attachNames) > 0 {
		fmt.Fprintf(&b, "题目附件（已挂载至 /work/.inputs）：%s\n", strings.Join(attachNames, ", "))
	}
	if ch.Description != "" {
		fmt.Fprintf(&b, "\n【题目描述】\n%s\n", ch.Description)
	}
	if ch.SubmissionType == "choice" {
		b.WriteString("\n请结合题目描述与附件完成分析，并通过 `benchmark_submit_choice` 提交正确选项 ID 数组。")
	} else {
		b.WriteString("\n请在隔离容器中完成题目分析与漏洞利用，拿到全部 Flag 并由系统或 `ctf_submit_flag` 提交验证。")
	}
	return b.String()
}

// ---- Runtime Hooks called by CTF Service & Agent ----

func (bm *BenchmarkManager) contextForTask(ctx context.Context, taskID int64, _ string) string {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	sess, ch, err := bm.s.m.pg.FindBenchmarkByTaskID(ctx, taskID)
	if err != nil || sess == nil || ch == nil {
		return ""
	}
	var meta struct {
		SubFlags []benchmark.SubFlagSpec `json:"sub_flags"`
		Choice   *benchmark.ChoiceMeta   `json:"choice"`
	}
	_ = json.Unmarshal(ch.Meta, &meta)
	cfg := parseSessionConfig(sess.Config)

	var b strings.Builder
	fmt.Fprintf(&b, "\n【测评题目元信息】平台=%s | 题目=%s (%s) | 进度=%d/%d Flag (%d/%d 分) | 状态=%s\n",
		sess.Provider, ch.UniqueCode, ch.Title, ch.CorrectFlagCount, ch.FlagCount, ch.CumulativeScore, ch.TotalScore, ch.ContainerStatus)
	if len(ch.ContainerAddr) > 0 {
		fmt.Fprintf(&b, "实时靶机地址：%s\n", strings.Join(ch.ContainerAddr, ", "))
	}
	if len(meta.SubFlags) > 0 {
		raw, _ := json.Marshal(meta.SubFlags)
		fmt.Fprintf(&b, "多 Flag 子项：%s\n", string(raw))
	}
	if meta.Choice != nil {
		raw, _ := json.Marshal(meta.Choice)
		fmt.Fprintf(&b, "【客观选择题选项（请调用 benchmark_submit_choice 提交）】：%s\n", string(raw))
	}
	if ch.HintContent != "" {
		fmt.Fprintf(&b, "【已获取 Hint】：%s\n", ch.HintContent)
	}
	if strings.TrimSpace(cfg.SkillInstructions) != "" {
		fmt.Fprintf(&b, "\n【接入平台 Skill 规范 (%s)】\n%s\n", cfg.SkillName, cfg.SkillInstructions)
	}
	return b.String()
}

func (bm *BenchmarkManager) extraToolsForTask(ctx context.Context, taskID int64) []actool.CoreTool {
	sess, ch, err := bm.s.m.pg.FindBenchmarkByTaskID(ctx, taskID)
	if err != nil || sess == nil || ch == nil || sess.Provider != "generic_mcp" {
		return nil
	}
	rt, err := bm.runtimeFor(sess)
	if err != nil {
		return nil
	}
	bm.mu.Lock()
	if rt.toolsLoaded {
		out := append([]actool.CoreTool(nil), rt.extraTools...)
		bm.mu.Unlock()
		return out
	}
	bm.mu.Unlock()

	gc, ok := rt.prov.(*benchmark.GenericMCPClient)
	if !ok {
		return nil
	}
	tctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	tools, derr := gc.DiscoverSafeTools(tctx)
	cancel()
	if derr != nil {
		return nil
	}
	bm.mu.Lock()
	rt.extraTools = tools
	rt.toolsLoaded = true
	bm.mu.Unlock()
	return tools
}

func (bm *BenchmarkManager) handleFlagCandidate(ctx context.Context, taskID int64, _ string, value, subFlagID string) (string, bool, error) {
	sess, ch, err := bm.s.m.pg.FindBenchmarkByTaskID(ctx, taskID)
	if err != nil || sess == nil || ch == nil {
		return "", false, nil
	}
	return bm.submitToPlatform(ctx, sess, ch, taskID, benchmark.SubmitRequest{
		UniqueCode: ch.UniqueCode,
		Flag:       strings.TrimSpace(value),
		SubFlagID:  strings.TrimSpace(subFlagID),
	}, strings.TrimSpace(value))
}

func (bm *BenchmarkManager) handleChoice(ctx context.Context, taskID int64, choices []string) (string, bool, error) {
	sess, ch, err := bm.s.m.pg.FindBenchmarkByTaskID(ctx, taskID)
	if err != nil || sess == nil || ch == nil {
		return "", false, nil
	}
	answerText := strings.Join(choices, ",")
	return bm.submitToPlatform(ctx, sess, ch, taskID, benchmark.SubmitRequest{
		UniqueCode: ch.UniqueCode,
		Choice:     choices,
	}, answerText)
}

// resolveBenchmarkCTFCandidates closes pending 'candidate' rows in ctf_candidates
// after automatic platform grading so zero-touch workers never enter an endless
// ctfSubmissionProvider waiting handoff loop.
func (bm *BenchmarkManager) resolveBenchmarkCTFCandidates(ctx context.Context, taskID int64, matchValue, state, notes string, finish bool) {
	t, ok := bm.s.m.Task(strconv.FormatInt(taskID, 10))
	if !ok || t == nil {
		return
	}
	cands, err := bm.s.m.pg.CTFCandidates(ctx, taskID)
	if err != nil {
		return
	}
	want := strings.TrimSpace(matchValue)
	for _, c := range cands {
		if c.State != "candidate" {
			continue
		}
		if want != "" && strings.TrimSpace(c.Value) != want {
			continue
		}
		if _, derr := bm.s.m.DecideCTFAnswer(ctx, t, c.ID, c.Revision, state, notes, finish); derr != nil {
			continue
		}
		// Only first Finish=true is needed; DecideCTFCandidate also batches sibling identical values.
		finish = false
	}
}

func (bm *BenchmarkManager) submitToPlatform(ctx context.Context, sess *db.BenchmarkSession, ch *db.BenchmarkChallenge, taskID int64, req benchmark.SubmitRequest, answerDisplay string) (string, bool, error) {
	if ch.IsCompleted {
		bm.resolveBenchmarkCTFCandidates(ctx, taskID, answerDisplay, "accepted", "该题已完成", false)
		return `{"correct":true,"already_completed":true,"message":"该题已完成"}`, true, nil
	}
	dup, _ := bm.s.m.pg.HasSubmittedBenchmarkAnswer(ctx, sess.ID, ch.UniqueCode, req.SubFlagID, answerDisplay)
	if dup {
		bm.resolveBenchmarkCTFCandidates(ctx, taskID, answerDisplay, "rejected", "该答案此前已向测评平台提交并被判错，切勿重复提交同一答案", false)
		return `{"correct":false,"duplicate":true,"message":"该答案已向测评平台提交并记录，切勿重复提交同一答案"}`, true, nil
	}
	rt, err := bm.runtimeFor(sess)
	if err != nil {
		return "", true, err
	}
	if time.Now().Before(rt.cooldownUntil) {
		wait := time.Until(rt.cooldownUntil)
		if wait > 5*time.Second {
			wait = 5 * time.Second
		}
		select {
		case <-ctx.Done():
			return "", true, ctx.Err()
		case <-time.After(wait):
		}
	}

	res, serr := rt.prov.SubmitAnswer(ctx, req)
	// Retry once on transient transport failure (http_status = 0, no structured API error).
	if serr != nil && (res == nil || (!res.Correct && res.HTTPStatus == 0)) {
		var seCheck *benchmark.StructuredError
		if !errors.As(serr, &seCheck) {
			select {
			case <-ctx.Done():
				return "", true, ctx.Err()
			case <-time.After(500 * time.Millisecond):
			}
			res, serr = rt.prov.SubmitAnswer(ctx, req)
		}
	}
	if res == nil {
		res = &benchmark.SubmitResult{Message: errString(serr)}
	}
	var se *benchmark.StructuredError
	if serr != nil && errors.As(serr, &se) {
		res.HTTPStatus = se.HTTPStatus
		res.Code = se.Code
		res.Message = se.Error()
		res.RetryAfterMs = se.RetryAfterMs
		if se.RetryAfterMs > 0 {
			rt.cooldownUntil = time.Now().Add(time.Duration(se.RetryAfterMs) * time.Millisecond)
		}
	}

	if serr != nil && !res.Correct && res.HTTPStatus == 0 {
		// Never write transport-failed (http_status=0) attempts into benchmark_submissions,
		// otherwise legitimate answers get permanently blocked by duplicate suppression.
		// Still reject the local pending candidate so Worker/Planner are not trapped.
		bm.resolveBenchmarkCTFCandidates(ctx, taskID, answerDisplay, "rejected", "平台网络传输异常（未完成裁决），请调整或重试提交："+serr.Error(), false)
		_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sess.ID, ch.UniqueCode, "submit_error", serr.Error(), nil)
		return "", true, serr
	}

	// Only persist platform-evaluated submissions (or corrected responses) into dedup history.
	if res.HTTPStatus == 0 && res.Correct {
		res.HTTPStatus = 200
	} else if res.HTTPStatus == 0 && serr == nil {
		res.HTTPStatus = 200
	}
	_ = bm.s.m.pg.RecordBenchmarkSubmission(ctx, db.BenchmarkSubmission{
		SessionID:        sess.ID,
		UniqueCode:       ch.UniqueCode,
		SubFlagID:        req.SubFlagID,
		AnswerValue:      answerDisplay,
		Correct:          res.Correct,
		Awarded:          res.Awarded,
		MatchedFlagIndex: res.MatchedFlagIndex,
		HTTPStatus:       res.HTTPStatus,
		ErrorCode:        res.Code,
		Message:          res.Message,
	})

	newScore := max(ch.CumulativeScore, res.CumulativeScore)
	if res.Correct && res.Awarded > 0 && res.CumulativeScore == 0 {
		newScore = ch.CumulativeScore + res.Awarded
	}
	newCorrectFlags := max(ch.CorrectFlagCount, res.CorrectFlagCount)
	if res.Correct && res.CorrectFlagCount == 0 {
		newCorrectFlags = ch.CorrectFlagCount + 1
	}
	totalFlags := max(ch.FlagCount, res.TotalFlagCount)
	completed := res.Completed || (res.Correct && newCorrectFlags >= max(1, totalFlags))

	_ = bm.s.m.pg.UpdateBenchmarkChallengeProgress(ctx, sess.ID, ch.UniqueCode, newScore, newCorrectFlags, totalFlags, completed)

	if res.Correct {
		bm.resolveBenchmarkCTFCandidates(ctx, taskID, answerDisplay, "accepted", "平台验证通过", completed)
	} else {
		bm.resolveBenchmarkCTFCandidates(ctx, taskID, answerDisplay, "rejected", "平台验证未通过："+res.Message, false)
	}

	taskIDStr := strconv.FormatInt(taskID, 10)
	if t, ok := bm.s.m.Task(taskIDStr); ok {
		if res.Correct {
			_, _ = t.Store.AddNode("fact", map[string]any{
				"summary":  fmt.Sprintf("【平台验真通过】%s 得分 +%d（当前 %d/%d Flag）", ch.UniqueCode, res.Awarded, newCorrectFlags, max(1, totalFlags)),
				"subtype":  "benchmark_verdict",
				"correct":  true,
				"complete": completed,
			}, 0, "confirmed", "benchmark", nil)
		} else {
			_, _ = t.Store.AddNode("fact", map[string]any{
				"summary": fmt.Sprintf("【平台验真拒绝】提交被平台判定错误（%s），严禁重复提交该值，请调整方向", res.Message),
				"subtype": "benchmark_verdict",
				"correct": false,
			}, 0, "confirmed", "benchmark", nil)
		}
		t.Notify()
	}

	if res.Correct {
		_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sess.ID, ch.UniqueCode, "flag_accepted",
			fmt.Sprintf("答案通过平台验证（+%d 分，完成=%v）", res.Awarded, completed), res)
		noteText := benchmark.RedactSensitive(fmt.Sprintf("Solved %s (%s), awarded %d score.", ch.UniqueCode, ch.Category, res.Awarded))
		_ = rt.prov.LogNote(ctx, ch.UniqueCode, "solve_summary", noteText)
	} else {
		_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sess.ID, ch.UniqueCode, "flag_rejected",
			fmt.Sprintf("答案未通过平台验证：%s", res.Message), res)
		if rejCount, rerr := bm.s.m.pg.CountRejectedBenchmarkSubmissions(ctx, sess.ID, ch.UniqueCode); rerr == nil && rejCount >= 6 {
			_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sess.ID, ch.UniqueCode, "flag_retry_limit",
				fmt.Sprintf("题目 %s 已被平台连续拒绝 %d 次答案，停止空转并释放并发槽位", ch.UniqueCode, rejCount), nil)
			bm.stopBoundTask(taskIDStr, "failed", fmt.Errorf("平台连续拒绝候选答案达上限 (%d 次)，终止空转释放槽位", rejCount))
			if ch.ContainerStatus == "available" || ch.ContainerStatus == "pending" {
				_ = rt.prov.CloseEnvironment(ctx, ch.UniqueCode)
				_ = bm.s.m.pg.UpdateBenchmarkChallengeEnv(ctx, sess.ID, ch.UniqueCode, "stopped", nil, nil, "")
			}
		}
	}

	if completed {
		bm.stopBoundTask(taskIDStr, "done", errors.New("测评题目已全部通关"))
		if ch.ContainerStatus == "available" || ch.ContainerStatus == "pending" {
			_ = rt.prov.CloseEnvironment(ctx, ch.UniqueCode)
			_ = bm.s.m.pg.UpdateBenchmarkChallengeEnv(ctx, sess.ID, ch.UniqueCode, "stopped", nil, nil, "")
		}
		_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sess.ID, ch.UniqueCode, "challenge_completed",
			fmt.Sprintf("题目 %s 已全部通关（总计 %d 分）", ch.UniqueCode, newScore), nil)
	}

	b, _ := json.Marshal(res)
	return string(b), true, nil
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
