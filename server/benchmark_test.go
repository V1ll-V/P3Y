package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"p3y/benchmark"
	"p3y/ctf"
	"p3y/db"
)

func TestBenchmarkSessionAndTaskIsolation(t *testing.T) {
	closedCalled := false
	mockTSec := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("BENCHMARK_TOKEN") != "tok-bench-1" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && r.URL.Path == "/openapi/v1/challenges":
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"unique_code":        "web-alpha",
				"description":        "Find the flag on web target",
				"difficulty":         "easy",
				"level":              1,
				"total_score":        200,
				"flag_count":         1,
				"correct_flag_count": 0,
				"is_completed":       false,
				"container_status":   "available",
				"container_addr":     []string{"127.0.0.1:9001"},
			}})
		case r.Method == "POST" && r.URL.Path == "/openapi/v1/challenges/submit":
			var body struct {
				UniqueCode string `json:"unique_code"`
				Flag       string `json:"flag"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.UniqueCode == "web-alpha" && body.Flag == "flag{right}" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"correct":            true,
					"awarded":            200,
					"cumulative_score":   200,
					"correct_flag_count": 1,
					"total_flag_count":   1,
				})
				return
			}
			w.WriteHeader(400)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"detail": map[string]any{
					"code":    "incorrect_flag",
					"message": "wrong flag",
				},
			})
		case r.Method == "POST" && r.URL.Path == "/openapi/v1/challenges/close" && r.URL.Query().Get("unique_code") == "web-alpha":
			closedCalled = true
			_ = json.NewEncoder(w).Encode(map[string]any{"unique_code": "web-alpha", "closed": true})
		default:
			w.WriteHeader(404)
		}
	}))
	defer mockTSec.Close()

	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer m.Close()

	td := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	s := New(ctx, m, td, td, td)
	h := s.Handler()
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	addAuth := func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	// 1. Create a benchmark session via HTTP API.
	createBody, _ := json.Marshal(map[string]any{
		"name":     "TSecBench Smoke",
		"provider": "tsecbench",
		"base_url": mockTSec.URL,
		"token":    "tok-bench-1",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/benchmarks", bytes.NewReader(createBody))
	req.Header.Set("Content-Type", "application/json")
	addAuth(req)
	h.ServeHTTP(rec, req)
	if rec.Code != 201 {
		t.Fatalf("POST /api/benchmarks status=%d body=%s", rec.Code, rec.Body.String())
	}
	var created db.BenchmarkSession
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created session: %v", err)
	}
	if created.TotalCount != 1 || created.MaxPossibleScore != 200 {
		t.Fatalf("unexpected created session aggregates: %+v", created)
	}

	// 2. Bind a zero-touch sub-task to the synced challenge and verify /api/tasks filters it out.
	sid := created.ID
	t.Cleanup(func() {
		cancel()
		delReq := httptest.NewRequest("DELETE", "/api/benchmarks/"+strconv.FormatInt(sid, 10), nil)
		addAuth(delReq)
		h.ServeHTTP(httptest.NewRecorder(), delReq)
	})
	subTask, err := s.m.CreateTaskWithOptions("Bench sub", "Solve flag", db.TaskCreateOptions{
		Name:               "[web-alpha] Alpha Web",
		Mode:               "ctf",
		ChallengeType:      "web",
		CTFVerifyMode:      db.CTFVerifyFlag,
		ZeroTouch:          true,
		BenchmarkSessionID: &sid,
	})
	if err != nil {
		t.Fatalf("CreateTaskWithOptions: %v", err)
	}
	tid, _ := strconv.ParseInt(subTask.ID, 10, 64)
	if err := s.m.pg.BindBenchmarkChallengeTask(t.Context(), sid, "web-alpha", tid); err != nil {
		t.Fatalf("BindBenchmarkChallengeTask: %v", err)
	}

	listRec := httptest.NewRecorder()
	listReq := httptest.NewRequest("GET", "/api/tasks", nil)
	addAuth(listReq)
	h.ServeHTTP(listRec, listReq)
	if listRec.Code != 200 {
		t.Fatalf("GET /api/tasks status=%d", listRec.Code)
	}
	var listedResp struct {
		Tasks []map[string]any `json:"tasks"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &listedResp); err != nil {
		t.Fatalf("decode /api/tasks: %v", err)
	}
	foundSubTask := false
	for _, item := range listedResp.Tasks {
		if fmt.Sprint(item["id"]) == subTask.ID {
			foundSubTask = true
			if item["benchmark_session_id"] == nil {
				t.Fatalf("benchmark sub-task missing benchmark_session_id in /api/tasks: %+v", item)
			}
		}
	}
	if !foundSubTask {
		t.Fatalf("expected benchmark sub-task %s to appear in /api/tasks for auditing", subTask.ID)
	}

	// Direct /api/tasks/{id} still resolves for drill-down inspection.
	getTaskRec := httptest.NewRecorder()
	getTaskReq := httptest.NewRequest("GET", "/api/tasks/"+subTask.ID, nil)
	addAuth(getTaskReq)
	h.ServeHTTP(getTaskRec, getTaskReq)
	if getTaskRec.Code != 200 {
		t.Fatalf("GET /api/tasks/{id} status=%d", getTaskRec.Code)
	}

	// 3. Submit wrong flag -> dedup check -> submit right flag -> challenge completed + closed.
	verdictWrong, handled, err := s.bench.handleFlagCandidate(t.Context(), tid, "exec-1", "flag{wrong}", "")
	if err != nil || !handled || !strings.Contains(verdictWrong, `"correct":false`) {
		t.Fatalf("wrong verdict unexpected: handled=%v err=%v verdict=%s", handled, err, verdictWrong)
	}
	verdictDup, handled, err := s.bench.handleFlagCandidate(t.Context(), tid, "exec-2", "flag{wrong}", "")
	if err != nil || !handled || !strings.Contains(verdictDup, `"duplicate":true`) {
		t.Fatalf("duplicate guard failed: handled=%v err=%v verdict=%s", handled, err, verdictDup)
	}
	verdictRight, handled, err := s.bench.handleFlagCandidate(t.Context(), tid, "exec-3", "flag{right}", "")
	if err != nil || !handled || !strings.Contains(verdictRight, `"completed":true`) {
		t.Fatalf("right verdict unexpected: handled=%v err=%v verdict=%s", handled, err, verdictRight)
	}
	if !closedCalled {
		t.Fatalf("expected mock TSecBench container close on completion")
	}

	// 4. Record token usage on the bound sub-task's exploration and verify
	// list, detail, and export endpoints report accurate session + challenge tokens.
	if _, err := s.m.pg.Exec(`
INSERT INTO activity(exploration_id, kind, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens)
VALUES ($1, 'result', 1200, 300, 500, 0), ($1, 'tool_result', 999, 999, 999, 999)`,
		subTask.ExpID); err != nil {
		t.Fatalf("insert mock activity: %v", err)
	}

	assertTokens := func(got db.BenchmarkTokenUsage, label string) {
		t.Helper()
		if got.InputTokens != 1200 || got.OutputTokens != 300 || got.CacheReadTokens != 500 || got.CacheWriteTokens != 0 || got.TotalTokens != 2000 {
			t.Fatalf("%s unexpected tokens: %+v", label, got)
		}
	}

	sessionsRec := httptest.NewRecorder()
	sessionsReq := httptest.NewRequest("GET", "/api/benchmarks", nil)
	addAuth(sessionsReq)
	h.ServeHTTP(sessionsRec, sessionsReq)
	if sessionsRec.Code != 200 {
		t.Fatalf("GET /api/benchmarks status=%d", sessionsRec.Code)
	}
	var sessionsList []db.BenchmarkSession
	if err := json.Unmarshal(sessionsRec.Body.Bytes(), &sessionsList); err != nil {
		t.Fatalf("decode sessions list: %v", err)
	}
	var foundListSess *db.BenchmarkSession
	for i := range sessionsList {
		if sessionsList[i].ID == sid {
			foundListSess = &sessionsList[i]
			break
		}
	}
	if foundListSess == nil {
		t.Fatalf("created session %d missing from GET /api/benchmarks", sid)
	}
	assertTokens(foundListSess.Tokens, "GET /api/benchmarks session")

	detailRec := httptest.NewRecorder()
	detailReq := httptest.NewRequest("GET", "/api/benchmarks/"+strconv.FormatInt(sid, 10), nil)
	addAuth(detailReq)
	h.ServeHTTP(detailRec, detailReq)
	if detailRec.Code != 200 {
		t.Fatalf("GET /api/benchmarks/{id} status=%d body=%s", detailRec.Code, detailRec.Body.String())
	}
	var detailPayload struct {
		Session    db.BenchmarkSession     `json:"session"`
		Challenges []db.BenchmarkChallenge `json:"challenges"`
	}
	if err := json.Unmarshal(detailRec.Body.Bytes(), &detailPayload); err != nil {
		t.Fatalf("decode session detail: %v", err)
	}
	if detailPayload.Session.TotalScore != 200 || detailPayload.Session.CompletedCount != 1 {
		t.Fatalf("expected completed score in session detail: %+v", detailPayload.Session)
	}
	assertTokens(detailPayload.Session.Tokens, "GET /api/benchmarks/{id} session")
	if len(detailPayload.Challenges) != 1 {
		t.Fatalf("expected 1 challenge in detail, got %d", len(detailPayload.Challenges))
	}
	assertTokens(detailPayload.Challenges[0].Tokens, "GET /api/benchmarks/{id} challenge")

	exportRec := httptest.NewRecorder()
	exportReq := httptest.NewRequest("GET", "/api/benchmarks/"+strconv.FormatInt(sid, 10)+"/export", nil)
	addAuth(exportReq)
	h.ServeHTTP(exportRec, exportReq)
	if exportRec.Code != 200 {
		t.Fatalf("GET /api/benchmarks/{id}/export status=%d", exportRec.Code)
	}
	var exportPayload struct {
		Session    db.BenchmarkSession     `json:"session"`
		Challenges []db.BenchmarkChallenge `json:"challenges"`
	}
	if err := json.Unmarshal(exportRec.Body.Bytes(), &exportPayload); err != nil {
		t.Fatalf("decode export payload: %v", err)
	}
	assertTokens(exportPayload.Session.Tokens, "GET /api/benchmarks/{id}/export session")
	if len(exportPayload.Challenges) != 1 {
		t.Fatalf("expected 1 challenge in export, got %d", len(exportPayload.Challenges))
	}
	assertTokens(exportPayload.Challenges[0].Tokens, "GET /api/benchmarks/{id}/export challenge")
}

type mockDetailFirstProvider struct {
	detailCalled bool
	envStarted   bool
}

func (m *mockDetailFirstProvider) Kind() string { return "ctf2" }
func (m *mockDetailFirstProvider) WhoAmI(context.Context) (*benchmark.AgentProfile, error) {
	return &benchmark.AgentProfile{MaxEnvironments: 1}, nil
}
func (m *mockDetailFirstProvider) ListChallenges(context.Context, benchmark.SessionConfig) ([]benchmark.ChallengeSpec, error) {
	return nil, nil
}
func (m *mockDetailFirstProvider) GetChallengeDetail(_ context.Context, id string) (*benchmark.ChallengeSpec, error) {
	m.detailCalled = true
	return &benchmark.ChallengeSpec{
		UniqueCode:     id,
		Title:          "unipickle",
		Description:    "Pickle RCE challenge on port 80",
		Category:       "web",
		Difficulty:     "Easy",
		SubmissionType: "flag",
		TotalScore:     100,
		FlagCount:      1,
		HasContainer:   true,
		Files:          []benchmark.AttachmentSpec{{ID: "f1", Name: "app.py", Size: 12}},
	}, nil
}
func (m *mockDetailFirstProvider) DownloadAttachment(_ context.Context, _, _ string) (string, []byte, error) {
	return "app.py", []byte("print('hi')\n"), nil
}
func (m *mockDetailFirstProvider) StartEnvironment(_ context.Context, id string) (*benchmark.EnvState, error) {
	if !m.detailCalled {
		return nil, errors.New("GetChallengeDetail must run before StartEnvironment")
	}
	m.envStarted = true
	return &benchmark.EnvState{
		UniqueCode: id,
		Status:     "available",
		Addrs:      []string{"https://unipickle.ctf2.test"},
	}, nil
}
func (m *mockDetailFirstProvider) GetEnvironment(context.Context, string) (*benchmark.EnvState, error) {
	return nil, nil
}
func (m *mockDetailFirstProvider) ExtendEnvironment(context.Context, string) (*benchmark.EnvState, error) {
	return nil, nil
}
func (m *mockDetailFirstProvider) CloseEnvironment(context.Context, string) error { return nil }
func (m *mockDetailFirstProvider) SubmitAnswer(context.Context, benchmark.SubmitRequest) (*benchmark.SubmitResult, error) {
	return nil, nil
}
func (m *mockDetailFirstProvider) GetHint(context.Context, string) (string, error) { return "", nil }
func (m *mockDetailFirstProvider) LogNote(context.Context, string, string, string) error {
	return nil
}

func TestBenchmarkSlotDetailBeforeStartAndNoSeedIntent(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer m.Close()

	td := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx, m, td, td, td)

	sess, err := s.m.pg.CreateBenchmarkSession(t.Context(), db.BenchmarkSessionCreate{
		Name:                "slot-order-test",
		Provider:            "ctf2",
		BaseURL:             "https://ctf2.example/api/ai/v1/mcp",
		MaxConcurrent:       3,
		HintPolicy:          "stagnant_only",
		PerChallengeTimeout: 600,
	})
	if err != nil {
		t.Fatalf("CreateBenchmarkSession: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		taskIDs, _ := s.m.pg.ListBenchmarkChallengeTaskIDs(context.Background(), sess.ID)
		for _, tid := range taskIDs {
			s.engine.StopTask(strconv.FormatInt(tid, 10))
			_, _ = s.m.DeleteTask(strconv.FormatInt(tid, 10), DeleteTaskOptions{})
		}
		_ = s.m.pg.DeleteBenchmarkSession(context.Background(), sess.ID)
	})

	// Seed a stale challenge row lacking description and claiming has_container=false.
	if err := s.m.pg.SyncBenchmarkChallenges(t.Context(), sess.ID, []db.BenchmarkChallengeUpsert{{
		UniqueCode:      "prac:pg1:ch1",
		Title:           "unipickle",
		Category:        "auto",
		Difficulty:      "Easy",
		SubmissionType:  "flag",
		TotalScore:      100,
		FlagCount:       1,
		ContainerStatus: "stopped",
		Meta:            json.RawMessage(`{"has_container":false}`),
	}}); err != nil {
		t.Fatalf("SyncBenchmarkChallenges: %v", err)
	}
	ch, err := s.m.pg.GetBenchmarkChallenge(t.Context(), sess.ID, "prac:pg1:ch1")
	if err != nil || ch == nil {
		t.Fatalf("GetBenchmarkChallenge: %v", err)
	}

	prov := &mockDetailFirstProvider{}
	rt := &benchSessionRuntime{
		prov:        prov,
		lastEnvPoll: map[string]time.Time{},
		taskStartAt: map[string]time.Time{},
	}

	// Quota already full (1 container running vs limit 1): detail fetch must discover
	// has_container=true and defer without starting container or blind task.
	launched, needsCont, err := s.bench.startChallengeSlot(t.Context(), rt, sess, ch, 1, 1)
	if !errors.Is(err, errBenchmarkQuotaDeferred) || launched || !needsCont {
		t.Fatalf("expected quota deferred, got launched=%v needsCont=%v err=%v", launched, needsCont, err)
	}
	if prov.envStarted {
		t.Fatalf("container must not start when quota is full")
	}

	// Reloaded challenge must already have fresh category, description, and has_container=true.
	reloaded, err := s.m.pg.GetBenchmarkChallenge(t.Context(), sess.ID, "prac:pg1:ch1")
	if err != nil || reloaded == nil {
		t.Fatalf("GetBenchmarkChallenge after detail: %v", err)
	}
	if reloaded.Category != "web" || !strings.Contains(reloaded.Description, "Pickle RCE") {
		t.Fatalf("detail fields not synced: category=%q desc=%q", reloaded.Category, reloaded.Description)
	}

	// With free container slot (0/1), startChallengeSlot must start container BEFORE
	// creating task, embed URL/desc/attachment into Goal, and leave frontier empty for Planner.
	launched, needsCont, err = s.bench.startChallengeSlot(t.Context(), rt, sess, reloaded, 1, 0)
	if err != nil || !launched || !needsCont || !prov.envStarted {
		t.Fatalf("expected launch success, got launched=%v needsCont=%v envStarted=%v err=%v", launched, needsCont, prov.envStarted, err)
	}
	after, _ := s.m.pg.GetBenchmarkChallenge(t.Context(), sess.ID, "prac:pg1:ch1")
	if after == nil || after.BoundTaskID == nil || after.ContainerStatus != "available" || len(after.ContainerAddr) != 1 {
		t.Fatalf("unexpected bound challenge state: %+v", after)
	}
	taskObj, ok := s.m.Task(strconv.FormatInt(*after.BoundTaskID, 10))
	if !ok || taskObj == nil {
		t.Fatalf("bound task #%d missing from manager", *after.BoundTaskID)
	}
	if !strings.Contains(taskObj.Goal, "https://unipickle.ctf2.test") ||
		!strings.Contains(taskObj.Goal, "Pickle RCE challenge on port 80") ||
		!strings.Contains(taskObj.Goal, "app.py") {
		t.Fatalf("task goal missing live URL, description, or attachment: %q", taskObj.Goal)
	}
	if hasActive, _ := taskObj.Store.HasActiveIntent(); hasActive {
		t.Fatalf("expected no pre-seeded monolithic intent so Planner round 1 triggers immediately")
	}
}

type mockQuotaStampedeProvider struct {
	startCalls   []string
	closedOrphan bool
}

func (m *mockQuotaStampedeProvider) Kind() string { return "ctf2" }
func (m *mockQuotaStampedeProvider) WhoAmI(context.Context) (*benchmark.AgentProfile, error) {
	return &benchmark.AgentProfile{MaxEnvironments: 1, ActiveEnvironments: 1}, nil
}
func (m *mockQuotaStampedeProvider) ListChallenges(context.Context, benchmark.SessionConfig) ([]benchmark.ChallengeSpec, error) {
	return nil, nil
}
func (m *mockQuotaStampedeProvider) GetChallengeDetail(_ context.Context, id string) (*benchmark.ChallengeSpec, error) {
	return &benchmark.ChallengeSpec{
		UniqueCode:     id,
		Title:          id,
		Description:    "Container challenge " + id,
		Category:       "web",
		Difficulty:     "Easy",
		SubmissionType: "flag",
		TotalScore:     100,
		FlagCount:      1,
		HasContainer:   true,
	}, nil
}
func (m *mockQuotaStampedeProvider) DownloadAttachment(context.Context, string, string) (string, []byte, error) {
	return "", nil, nil
}
func (m *mockQuotaStampedeProvider) StartEnvironment(_ context.Context, id string) (*benchmark.EnvState, error) {
	m.startCalls = append(m.startCalls, id)
	return nil, &benchmark.StructuredError{
		HTTPStatus: 400,
		Code:       "agent_environment_limit",
		Message:    "This Agent already runs its maximum number of environments.",
	}
}
func (m *mockQuotaStampedeProvider) GetEnvironment(_ context.Context, id string) (*benchmark.EnvState, error) {
	if id == "prac:pg1:orphan" && !m.closedOrphan {
		return &benchmark.EnvState{
			UniqueCode: id,
			Status:     "available",
			Addrs:      []string{"https://orphan.ctf2.test"},
		}, nil
	}
	return &benchmark.EnvState{UniqueCode: id, Status: "stopped"}, nil
}
func (m *mockQuotaStampedeProvider) ExtendEnvironment(context.Context, string) (*benchmark.EnvState, error) {
	return nil, nil
}
func (m *mockQuotaStampedeProvider) CloseEnvironment(_ context.Context, id string) error {
	if id == "prac:pg1:orphan" {
		m.closedOrphan = true
	}
	return nil
}
func (m *mockQuotaStampedeProvider) SubmitAnswer(context.Context, benchmark.SubmitRequest) (*benchmark.SubmitResult, error) {
	return nil, nil
}
func (m *mockQuotaStampedeProvider) GetHint(context.Context, string) (string, error) { return "", nil }
func (m *mockQuotaStampedeProvider) LogNote(context.Context, string, string, string) error {
	return nil
}

func TestBenchmarkQuotaLimitReclaimAndNoStampede(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer m.Close()

	td := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx, m, td, td, td)

	sess, err := s.m.pg.CreateBenchmarkSession(t.Context(), db.BenchmarkSessionCreate{
		Name:                "quota-reclaim-test",
		Provider:            "ctf2",
		BaseURL:             "https://ctf2.example/api/ai/v1/mcp",
		MaxConcurrent:       3,
		HintPolicy:          "never",
		PerChallengeTimeout: 600,
	})
	if err != nil {
		t.Fatalf("CreateBenchmarkSession: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = s.m.pg.DeleteBenchmarkSession(context.Background(), sess.ID)
	})

	if err := s.m.pg.SyncBenchmarkChallenges(t.Context(), sess.ID, []db.BenchmarkChallengeUpsert{
		{
			UniqueCode:      "prac:pg1:alpha",
			Title:           "alpha",
			Category:        "web",
			SubmissionType:  "flag",
			TotalScore:      100,
			FlagCount:       1,
			ContainerStatus: "stopped",
			Meta:            json.RawMessage(`{"has_container":true}`),
		},
		{
			UniqueCode:      "prac:pg1:beta",
			Title:           "beta",
			Category:        "web",
			SubmissionType:  "flag",
			TotalScore:      100,
			FlagCount:       1,
			ContainerStatus: "stopped",
			Meta:            json.RawMessage(`{"has_container":true}`),
		},
		{
			UniqueCode:      "prac:pg1:orphan",
			Title:           "orphan",
			Category:        "web",
			SubmissionType:  "flag",
			TotalScore:      100,
			FlagCount:       1,
			ContainerStatus: "stopped",
			Meta:            json.RawMessage(`{"has_container":true}`),
		},
	}); err != nil {
		t.Fatalf("SyncBenchmarkChallenges: %v", err)
	}
	// Seed a prior attempt and a stale agent_environment_limit error on beta/orphan.
	_ = s.m.pg.UpdateBenchmarkSessionStatus(t.Context(), sess.ID, "running", "")
	_ = s.m.pg.UpdateBenchmarkChallengeEnv(t.Context(), sess.ID, "prac:pg1:orphan", "stopped", nil, nil, "agent_environment_limit (400)")
	_ = s.m.pg.UpdateBenchmarkChallengeEnv(t.Context(), sess.ID, "prac:pg1:beta", "stopped", nil, nil, "agent_environment_limit (400)")
	_ = s.m.pg.BindBenchmarkChallengeTask(t.Context(), sess.ID, "prac:pg1:orphan", 999999)

	prov := &mockQuotaStampedeProvider{}
	rt := &benchSessionRuntime{
		sessionID:   sess.ID,
		prov:        prov,
		lastEnvPoll: map[string]time.Time{},
		taskStartAt: map[string]time.Time{},
	}
	s.bench.mu.Lock()
	s.bench.runs[sess.ID] = rt
	s.bench.mu.Unlock()
	t.Cleanup(func() {
		s.bench.mu.Lock()
		delete(s.bench.runs, sess.ID)
		s.bench.mu.Unlock()
	})

	if err := s.bench.tickSession(t.Context(), sess.ID, rt, 1); err != nil {
		t.Fatalf("tickSession: %v", err)
	}

	if len(prov.startCalls) != 1 || prov.startCalls[0] != "prac:pg1:alpha" {
		t.Fatalf("expected exactly 1 StartEnvironment call on alpha (no stampede to beta), got %v", prov.startCalls)
	}
	if !prov.closedOrphan {
		t.Fatalf("expected leaked remote orphan container to be closed automatically")
	}
	alpha, _ := s.m.pg.GetBenchmarkChallenge(t.Context(), sess.ID, "prac:pg1:alpha")
	beta, _ := s.m.pg.GetBenchmarkChallenge(t.Context(), sess.ID, "prac:pg1:beta")
	orphan, _ := s.m.pg.GetBenchmarkChallenge(t.Context(), sess.ID, "prac:pg1:orphan")
	if alpha == nil || alpha.LastError != "" {
		t.Fatalf("alpha must not be stamped red on quota limit, got %+v", alpha)
	}
	if beta == nil || beta.LastError != "" {
		t.Fatalf("beta stale quota error must be cleared after reclaim, got %+v", beta)
	}
	if orphan == nil || orphan.LastError != "" || orphan.ContainerStatus != "stopped" {
		t.Fatalf("orphan should be cleanly closed & error cleared, got %+v", orphan)
	}
}

func TestBenchmarkRecoverInterruptedEmptyDescAndRetryEndpoint(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer m.Close()

	td := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx, m, td, td, td)
	h := s.Handler()
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	addAuth := func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	sess, err := s.m.pg.CreateBenchmarkSession(t.Context(), db.BenchmarkSessionCreate{
		Name:                "recover-empty-desc-test",
		Provider:            "ctf2",
		BaseURL:             "https://ctf2.example/api/ai/v1/mcp",
		MaxConcurrent:       2,
		HintPolicy:          "never",
		PerChallengeTimeout: 600,
	})
	if err != nil {
		t.Fatalf("CreateBenchmarkSession: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		taskIDs, _ := s.m.pg.ListBenchmarkChallengeTaskIDs(context.Background(), sess.ID)
		for _, tid := range taskIDs {
			s.engine.StopTask(strconv.FormatInt(tid, 10))
			_, _ = s.m.DeleteTask(strconv.FormatInt(tid, 10), DeleteTaskOptions{})
		}
		_ = s.m.pg.DeleteBenchmarkSession(context.Background(), sess.ID)
	})

	// Create an old failed task that represents a pre-fix interrupted run (empty description).
	oldTask, err := s.m.CreateTaskWithOptions("old failed", "missing desc", db.TaskCreateOptions{
		Name:               "[prac:pg1:ch1] unipickle",
		Mode:               "ctf",
		ZeroTouch:          true,
		BenchmarkSessionID: &sess.ID,
	})
	if err != nil {
		t.Fatalf("CreateTaskWithOptions old failed: %v", err)
	}
	_ = s.m.SetTaskStatus(oldTask.ID, "failed")
	oldTID, _ := strconv.ParseInt(oldTask.ID, 10, 64)

	if err := s.m.pg.SyncBenchmarkChallenges(t.Context(), sess.ID, []db.BenchmarkChallengeUpsert{
		{
			UniqueCode:      "prac:pg1:ch1",
			Title:           "unipickle",
			Description:     "",
			Category:        "auto",
			SubmissionType:  "flag",
			TotalScore:      100,
			FlagCount:       1,
			ContainerStatus: "stopped",
			Meta:            json.RawMessage(`{"has_container":false}`),
		},
		{
			UniqueCode:       "prac:pg1:done",
			Title:            "already-solved",
			Description:      "Solved challenge",
			Category:         "misc",
			SubmissionType:   "flag",
			TotalScore:       100,
			CumulativeScore:  100,
			FlagCount:        1,
			CorrectFlagCount: 1,
			IsCompleted:      true,
			ContainerStatus:  "stopped",
		},
	}); err != nil {
		t.Fatalf("SyncBenchmarkChallenges: %v", err)
	}
	_ = s.m.pg.BindBenchmarkChallengeTask(t.Context(), sess.ID, "prac:pg1:ch1", oldTID)
	_ = s.m.pg.UpdateBenchmarkSessionStatus(t.Context(), sess.ID, "running", "")

	// GET detail should surface bound_task_status="failed".
	getRec := httptest.NewRecorder()
	getReq := httptest.NewRequest("GET", "/api/benchmarks/"+strconv.FormatInt(sess.ID, 10), nil)
	addAuth(getReq)
	h.ServeHTTP(getRec, getReq)
	if getRec.Code != 200 {
		t.Fatalf("GET detail status=%d", getRec.Code)
	}
	var detail struct {
		Challenges []db.BenchmarkChallenge `json:"challenges"`
	}
	if err := json.Unmarshal(getRec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("decode detail: %v", err)
	}
	var gotCh1 *db.BenchmarkChallenge
	for i := range detail.Challenges {
		if detail.Challenges[i].UniqueCode == "prac:pg1:ch1" {
			gotCh1 = &detail.Challenges[i]
		}
	}
	if gotCh1 == nil || gotCh1.BoundTaskStatus != "failed" {
		t.Fatalf("expected bound_task_status=failed on GET detail, got %+v", gotCh1)
	}

	// tickSession must auto-reset the zero-description interrupted challenge and relaunch it with fresh detail.
	prov := &mockDetailFirstProvider{}
	rt := &benchSessionRuntime{
		sessionID:   sess.ID,
		prov:        prov,
		lastEnvPoll: map[string]time.Time{},
		taskStartAt: map[string]time.Time{},
	}
	s.bench.mu.Lock()
	s.bench.runs[sess.ID] = rt
	s.bench.mu.Unlock()
	t.Cleanup(func() {
		s.bench.mu.Lock()
		delete(s.bench.runs, sess.ID)
		s.bench.mu.Unlock()
	})

	if err := s.bench.tickSession(t.Context(), sess.ID, rt, 1); err != nil {
		t.Fatalf("tickSession: %v", err)
	}
	reloaded, _ := s.m.pg.GetBenchmarkChallenge(t.Context(), sess.ID, "prac:pg1:ch1")
	if reloaded == nil || reloaded.BoundTaskID == nil || *reloaded.BoundTaskID == oldTID {
		t.Fatalf("expected fresh bound task replacing %d, got %+v", oldTID, reloaded)
	}
	if !prov.detailCalled || !prov.envStarted || !strings.Contains(reloaded.Description, "Pickle RCE") {
		t.Fatalf("expected detail + env + description recovery, detail=%v env=%v desc=%q", prov.detailCalled, prov.envStarted, reloaded.Description)
	}

	// Test retry-failed HTTP endpoint on an interrupted challenge with non-empty description.
	_ = s.m.SetTaskStatus(strconv.FormatInt(*reloaded.BoundTaskID, 10), "failed")
	retryRec := httptest.NewRecorder()
	retryReq := httptest.NewRequest("POST", "/api/benchmarks/"+strconv.FormatInt(sess.ID, 10)+"/retry-failed", nil)
	addAuth(retryReq)
	h.ServeHTTP(retryRec, retryReq)
	if retryRec.Code != 200 {
		t.Fatalf("POST retry-failed status=%d body=%s", retryRec.Code, retryRec.Body.String())
	}
	var retryResp struct {
		Reset int64 `json:"reset"`
	}
	_ = json.Unmarshal(retryRec.Body.Bytes(), &retryResp)
	if retryResp.Reset != 1 {
		t.Fatalf("expected reset=1 failed challenge, got %+v", retryResp)
	}
	afterRetry, _ := s.m.pg.GetBenchmarkChallenge(t.Context(), sess.ID, "prac:pg1:ch1")
	afterDone, _ := s.m.pg.GetBenchmarkChallenge(t.Context(), sess.ID, "prac:pg1:done")
	if afterRetry == nil || afterRetry.BoundTaskID != nil || afterRetry.AttemptCount != 0 {
		t.Fatalf("expected ch1 reset to attempt_count=0 & unbound, got %+v", afterRetry)
	}
	if afterDone == nil || !afterDone.IsCompleted {
		t.Fatalf("completed challenge must stay completed, got %+v", afterDone)
	}
}

type mockSubmitAndMaintenanceProvider struct {
	detailCalls   []string
	submitCalls   []string
	failTransport bool
	failMaint     bool
}

func (m *mockSubmitAndMaintenanceProvider) Kind() string { return "ctf2" }
func (m *mockSubmitAndMaintenanceProvider) WhoAmI(context.Context) (*benchmark.AgentProfile, error) {
	return &benchmark.AgentProfile{MaxEnvironments: 3, ActiveEnvironments: 0}, nil
}
func (m *mockSubmitAndMaintenanceProvider) ListChallenges(context.Context, benchmark.SessionConfig) ([]benchmark.ChallengeSpec, error) {
	return nil, nil
}
func (m *mockSubmitAndMaintenanceProvider) GetChallengeDetail(_ context.Context, id string) (*benchmark.ChallengeSpec, error) {
	m.detailCalls = append(m.detailCalls, id)
	if m.failMaint {
		return nil, &benchmark.StructuredError{
			HTTPStatus: 400,
			Code:       "maintenance_mode",
			Message:    "System maintenance in progress",
			Retryable:  true,
		}
	}
	return &benchmark.ChallengeSpec{
		UniqueCode:     id,
		Title:          id,
		Description:    "Solve " + id,
		Category:       "misc",
		SubmissionType: "flag",
		TotalScore:     100,
		FlagCount:      1,
		HasContainer:   false,
	}, nil
}
func (m *mockSubmitAndMaintenanceProvider) DownloadAttachment(context.Context, string, string) (string, []byte, error) {
	return "", nil, nil
}
func (m *mockSubmitAndMaintenanceProvider) StartEnvironment(_ context.Context, id string) (*benchmark.EnvState, error) {
	return &benchmark.EnvState{UniqueCode: id, Status: "stopped"}, nil
}
func (m *mockSubmitAndMaintenanceProvider) GetEnvironment(_ context.Context, id string) (*benchmark.EnvState, error) {
	return &benchmark.EnvState{UniqueCode: id, Status: "stopped"}, nil
}
func (m *mockSubmitAndMaintenanceProvider) ExtendEnvironment(context.Context, string) (*benchmark.EnvState, error) {
	return nil, nil
}
func (m *mockSubmitAndMaintenanceProvider) CloseEnvironment(context.Context, string) error {
	return nil
}
func (m *mockSubmitAndMaintenanceProvider) SubmitAnswer(_ context.Context, req benchmark.SubmitRequest) (*benchmark.SubmitResult, error) {
	m.submitCalls = append(m.submitCalls, req.Flag)
	if m.failTransport {
		return nil, errors.New("stream error: stream ID 355; INTERNAL_ERROR")
	}
	if req.Flag == "sun{right_flag}" {
		return &benchmark.SubmitResult{
			Correct:          true,
			Awarded:          100,
			CumulativeScore:  100,
			CorrectFlagCount: 1,
			TotalFlagCount:   1,
			Completed:        true,
			HTTPStatus:       200,
		}, nil
	}
	return &benchmark.SubmitResult{
			Correct:    false,
			HTTPStatus: 400,
			Code:       "incorrect_flag",
			Message:    "wrong flag",
		}, &benchmark.StructuredError{
			HTTPStatus: 400,
			Code:       "incorrect_flag",
			Message:    "wrong flag",
		}
}
func (m *mockSubmitAndMaintenanceProvider) GetHint(context.Context, string) (string, error) {
	return "", nil
}
func (m *mockSubmitAndMaintenanceProvider) LogNote(context.Context, string, string, string) error {
	return nil
}

func TestBenchmarkSubmitLoopPreventionAndMaintenanceCooldown(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer m.Close()

	td := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx, m, td, td, td)

	sess, err := s.m.pg.CreateBenchmarkSession(t.Context(), db.BenchmarkSessionCreate{
		Name:                "loop-and-maint-test",
		Provider:            "ctf2",
		BaseURL:             "https://ctf2.example/api/ai/v1/mcp",
		MaxConcurrent:       3,
		HintPolicy:          "never",
		PerChallengeTimeout: 600,
	})
	if err != nil {
		t.Fatalf("CreateBenchmarkSession: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		taskIDs, _ := s.m.pg.ListBenchmarkChallengeTaskIDs(context.Background(), sess.ID)
		for _, tid := range taskIDs {
			s.engine.StopTask(strconv.FormatInt(tid, 10))
			_, _ = s.m.DeleteTask(strconv.FormatInt(tid, 10), DeleteTaskOptions{})
		}
		_ = s.m.pg.DeleteBenchmarkSession(context.Background(), sess.ID)
	})

	if err := s.m.pg.SyncBenchmarkChallenges(t.Context(), sess.ID, []db.BenchmarkChallengeUpsert{
		{
			UniqueCode:      "prac:pg1:noflag",
			Title:           "[5.1.3 摩斯密码][无flag]摩斯密码",
			Description:     "第5.1.3 摩斯密码节配套附件，本题无flag",
			Category:        "misc",
			SubmissionType:  "flag",
			TotalScore:      1,
			FlagCount:       1,
			ContainerStatus: "stopped",
		},
		{
			UniqueCode:      "prac:pg1:q1",
			Title:           "BigMak",
			Description:     "Find flag",
			Category:        "misc",
			SubmissionType:  "flag",
			TotalScore:      100,
			FlagCount:       1,
			ContainerStatus: "stopped",
		},
		{
			UniqueCode:      "prac:pg1:q2",
			Title:           "Second",
			Description:     "Second challenge",
			Category:        "misc",
			SubmissionType:  "flag",
			TotalScore:      100,
			FlagCount:       1,
			ContainerStatus: "stopped",
		},
	}); err != nil {
		t.Fatalf("SyncBenchmarkChallenges: %v", err)
	}
	_ = s.m.pg.UpdateBenchmarkSessionStatus(t.Context(), sess.ID, "running", "")

	prov := &mockSubmitAndMaintenanceProvider{failMaint: true}
	rt := &benchSessionRuntime{
		sessionID:   sess.ID,
		prov:        prov,
		lastEnvPoll: map[string]time.Time{},
		taskStartAt: map[string]time.Time{},
	}
	s.bench.mu.Lock()
	s.bench.runs[sess.ID] = rt
	s.bench.mu.Unlock()
	t.Cleanup(func() {
		s.bench.mu.Lock()
		delete(s.bench.runs, sess.ID)
		s.bench.mu.Unlock()
	})

	// 1. No-flag entry must be skipped, and maintenance_mode on q1 must trip cooldown without touching q2 or stamping errors.
	if err := s.bench.tickSession(t.Context(), sess.ID, rt, 1); err != nil {
		t.Fatalf("tickSession maint: %v", err)
	}
	if len(prov.detailCalls) != 1 || prov.detailCalls[0] != "prac:pg1:q1" {
		t.Fatalf("expected only q1 detail attempt before circuit break (skipping noflag and stopping before q2), got %v", prov.detailCalls)
	}
	if !time.Now().Before(rt.cooldownUntil) {
		t.Fatalf("expected cooldownUntil in future after maintenance_mode, got %v", rt.cooldownUntil)
	}
	q1, _ := s.m.pg.GetBenchmarkChallenge(t.Context(), sess.ID, "prac:pg1:q1")
	q2, _ := s.m.pg.GetBenchmarkChallenge(t.Context(), sess.ID, "prac:pg1:q2")
	noflag, _ := s.m.pg.GetBenchmarkChallenge(t.Context(), sess.ID, "prac:pg1:noflag")
	if q1.LastError != "" || q2.LastError != "" || noflag.BoundTaskID != nil {
		t.Fatalf("expected clean challenges and unbound noflag, q1=%q q2=%q noflagTask=%v", q1.LastError, q2.LastError, noflag.BoundTaskID)
	}

	// 2. Bind a zero-touch task to q1 and verify submission dedup/candidate lifecycle.
	taskObj, err := s.m.CreateTaskWithOptions("BigMak", "Find flag", db.TaskCreateOptions{
		Name:               "[prac:pg1:q1] BigMak",
		Mode:               "ctf",
		ZeroTouch:          true,
		BenchmarkSessionID: &sess.ID,
	})
	if err != nil {
		t.Fatalf("CreateTaskWithOptions: %v", err)
	}
	tidNum, _ := strconv.ParseInt(taskObj.ID, 10, 64)
	_ = s.m.pg.BindBenchmarkChallengeTask(t.Context(), sess.ID, "prac:pg1:q1", tidNum)
	_ = s.ctfService().Sync(t.Context(), tidNum)
	var inputHash string
	if err := s.m.pg.QueryRow(`SELECT ctf_input_hash FROM tasks WHERE id=$1`, tidNum).Scan(&inputHash); err != nil {
		t.Fatalf("query ctf_input_hash: %v", err)
	}
	execRow := &db.CTFExecution{
		ID:        "exec-loop-test-1",
		TaskID:    tidNum,
		InputHash: inputHash,
		StartedAt: time.Now(),
	}
	if err := s.m.pg.SaveCTFExecution(t.Context(), execRow); err != nil {
		t.Fatalf("SaveCTFExecution: %v", err)
	}
	submitCandidate := func(flag string) (string, bool, error) {
		if _, err := s.m.pg.AddCTFCandidate(t.Context(), tidNum, execRow.ID, flag); err != nil {
			t.Fatalf("AddCTFCandidate(%s): %v", flag, err)
		}
		return s.bench.handleFlagCandidate(t.Context(), tidNum, execRow.ID, flag, "")
	}

	// 2a. Structured wrong flag must close candidate as 'rejected' so PendingCTFSubmission stays nil (no handoff loop).
	rt.cooldownUntil = time.Time{}
	prov.failMaint = false
	prov.failTransport = false
	if _, _, err := submitCandidate("sun{wrong_flag}"); err != nil {
		t.Fatalf("handleFlagCandidate wrong: %v", err)
	}
	if pending, _ := s.m.pg.PendingCTFSubmission(t.Context(), tidNum); pending != nil {
		t.Fatalf("expected nil PendingCTFSubmission after rejected platform flag, got %+v", pending)
	}
	// Duplicate wrong flag must also keep PendingCTFSubmission nil.
	if _, _, err := submitCandidate("sun{wrong_flag}"); err != nil {
		t.Fatalf("handleFlagCandidate dup wrong: %v", err)
	}
	if pending, _ := s.m.pg.PendingCTFSubmission(t.Context(), tidNum); pending != nil {
		t.Fatalf("expected nil PendingCTFSubmission on duplicate wrong flag, got %+v", pending)
	}

	// 2b. Transient transport error (http_status=0) must retry once, NOT poison benchmark_submissions,
	// and close the local candidate so the correct flag can still be submitted immediately afterwards.
	prov.submitCalls = nil
	prov.failTransport = true
	if _, _, err := submitCandidate("sun{right_flag}"); err == nil {
		t.Fatalf("expected transport error when platform stream fails")
	}
	if len(prov.submitCalls) != 2 {
		t.Fatalf("expected 1x retry (2 total SubmitAnswer calls) on transient transport failure, got %d", len(prov.submitCalls))
	}
	if pending, _ := s.m.pg.PendingCTFSubmission(t.Context(), tidNum); pending != nil {
		t.Fatalf("expected nil PendingCTFSubmission after transport error, got %+v", pending)
	}
	if dup, _ := s.m.pg.HasSubmittedBenchmarkAnswer(t.Context(), sess.ID, "prac:pg1:q1", "", "sun{right_flag}"); dup {
		t.Fatalf("transport failure must NOT poison duplicate dedup table")
	}

	// 2c. Retrying the exact same real flag once network recovers must succeed and complete the challenge.
	prov.failTransport = false
	out, handled, err := submitCandidate("sun{right_flag}")
	if err != nil || !handled || !strings.Contains(out, `"correct":true`) {
		t.Fatalf("expected successful submission after transport recovery, handled=%v out=%q err=%v", handled, out, err)
	}
	if pending, _ := s.m.pg.PendingCTFSubmission(t.Context(), tidNum); pending != nil {
		t.Fatalf("expected nil PendingCTFSubmission after accepted flag, got %+v", pending)
	}
	doneQ1, _ := s.m.pg.GetBenchmarkChallenge(t.Context(), sess.ID, "prac:pg1:q1")
	if doneQ1 == nil || !doneQ1.IsCompleted {
		t.Fatalf("expected q1 to be marked completed, got %+v", doneQ1)
	}
}

func TestBenchmarkTimeoutSettingsAutoRetryAndMemoryInheritance(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer m.Close()

	td := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx, m, td, td, td)
	h := s.Handler()
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	addAuth := func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	// Default per_challenge_timeout should be 5400s (90 minutes) when omitted.
	sess, err := s.m.pg.CreateBenchmarkSession(t.Context(), db.BenchmarkSessionCreate{
		Name:          "auto-retry-inherit-test",
		Provider:      "ctf2",
		BaseURL:       "https://ctf2.example/api/ai/v1/mcp",
		MaxConcurrent: 2,
		HintPolicy:    "never",
	})
	if err != nil {
		t.Fatalf("CreateBenchmarkSession: %v", err)
	}
	if sess.PerChallengeTimeout != 5400 {
		t.Fatalf("expected default PerChallengeTimeout=5400, got %d", sess.PerChallengeTimeout)
	}
	t.Cleanup(func() {
		cancel()
		taskIDs, _ := s.m.pg.ListBenchmarkChallengeTaskIDs(context.Background(), sess.ID)
		for _, tid := range taskIDs {
			s.engine.StopTask(strconv.FormatInt(tid, 10))
			_, _ = s.m.DeleteTask(strconv.FormatInt(tid, 10), DeleteTaskOptions{})
		}
		_ = s.m.pg.DeleteBenchmarkSession(context.Background(), sess.ID)
	})

	// PATCH /api/benchmarks/{id} updates budget and concurrency dynamically.
	patchRec := httptest.NewRecorder()
	patchReq := httptest.NewRequest("PATCH", "/api/benchmarks/"+strconv.FormatInt(sess.ID, 10),
		strings.NewReader(`{"max_concurrent":4,"per_challenge_timeout":7200}`))
	patchReq.Header.Set("Content-Type", "application/json")
	addAuth(patchReq)
	h.ServeHTTP(patchRec, patchReq)
	if patchRec.Code != 200 {
		t.Fatalf("PATCH /api/benchmarks/{id} status=%d body=%s", patchRec.Code, patchRec.Body.String())
	}
	var updatedSess db.BenchmarkSession
	if err := json.Unmarshal(patchRec.Body.Bytes(), &updatedSess); err != nil {
		t.Fatalf("decode updated session: %v", err)
	}
	if updatedSess.MaxConcurrent != 4 || updatedSess.PerChallengeTimeout != 7200 {
		t.Fatalf("unexpected patched session: %+v", updatedSess)
	}

	// Seed challenge with an existing timed-out task so auto-retry cooldown & SourceTaskIDs inheritance run end-to-end.
	oldTask, err := s.m.CreateTaskWithOptions("prev timed-out", "old goal", db.TaskCreateOptions{
		Name:               "[prac:pg1:ch1] unipickle",
		Mode:               "ctf",
		ZeroTouch:          true,
		BenchmarkSessionID: &sess.ID,
	})
	if err != nil {
		t.Fatalf("CreateTaskWithOptions oldTask: %v", err)
	}
	_ = s.m.SetTaskStatus(oldTask.ID, "timeout")
	oldTID, _ := strconv.ParseInt(oldTask.ID, 10, 64)

	if err := s.m.pg.SyncBenchmarkChallenges(t.Context(), sess.ID, []db.BenchmarkChallengeUpsert{{
		UniqueCode:      "prac:pg1:ch1",
		Title:           "unipickle",
		Description:     "Existing description before timeout",
		Category:        "web",
		SubmissionType:  "flag",
		TotalScore:      100,
		FlagCount:       1,
		ContainerStatus: "stopped",
		Meta:            json.RawMessage(`{"has_container":false}`),
	}}); err != nil {
		t.Fatalf("SyncBenchmarkChallenges: %v", err)
	}
	_ = s.m.pg.BindBenchmarkChallengeTask(t.Context(), sess.ID, "prac:pg1:ch1", oldTID)
	_ = s.m.pg.UpdateBenchmarkSessionStatus(t.Context(), sess.ID, "running", "")

	prov := &mockDetailFirstProvider{}
	rt := &benchSessionRuntime{
		sessionID:   sess.ID,
		prov:        prov,
		lastEnvPoll: map[string]time.Time{},
		taskStartAt: map[string]time.Time{},
	}
	s.bench.mu.Lock()
	s.bench.runs[sess.ID] = rt
	s.bench.mu.Unlock()
	t.Cleanup(func() {
		s.bench.mu.Lock()
		delete(s.bench.runs, sess.ID)
		s.bench.mu.Unlock()
	})

	// Tick 1: newly observed timeout task enters cooldown without immediately recreating a task.
	if err := s.bench.tickSession(t.Context(), sess.ID, rt, 1); err != nil {
		t.Fatalf("tickSession #1: %v", err)
	}
	cooling, _ := s.m.pg.GetBenchmarkChallenge(t.Context(), sess.ID, "prac:pg1:ch1")
	if cooling == nil || cooling.NextRetryAt == nil || cooling.AutoRetryCount != 1 {
		t.Fatalf("expected cooldown scheduled (auto_retry_count=1, next_retry_at set), got %+v", cooling)
	}
	if cooling.BoundTaskID == nil || *cooling.BoundTaskID != oldTID {
		t.Fatalf("expected bound_task_id preserved during cooldown, got %+v", cooling.BoundTaskID)
	}

	// Simulate cooldown elapsed.
	past := time.Now().Add(-1 * time.Second)
	if err := s.m.pg.ScheduleBenchmarkChallengeRetry(t.Context(), sess.ID, "prac:pg1:ch1", &past, 1, cooling.LastError); err != nil {
		t.Fatalf("ScheduleBenchmarkChallengeRetry past: %v", err)
	}

	// Tick 2: expired cooldown automatically requeues and creates a new task inheriting oldTID.
	if err := s.bench.tickSession(t.Context(), sess.ID, rt, 1); err != nil {
		t.Fatalf("tickSession #2: %v", err)
	}
	relaunched, _ := s.m.pg.GetBenchmarkChallenge(t.Context(), sess.ID, "prac:pg1:ch1")
	if relaunched == nil || relaunched.BoundTaskID == nil || *relaunched.BoundTaskID == oldTID {
		t.Fatalf("expected new bound_task_id replacing %d, got %+v", oldTID, relaunched)
	}
	newTask, ok := s.m.Task(strconv.FormatInt(*relaunched.BoundTaskID, 10))
	if !ok || newTask == nil {
		t.Fatalf("new bound task %d missing in manager", *relaunched.BoundTaskID)
	}
	snap := newTask.lifecycleSnapshot()
	if len(snap.SourceTaskIDs) != 1 || snap.SourceTaskIDs[0] != oldTID {
		t.Fatalf("expected new task SourceTaskIDs=[%d], got %+v", oldTID, snap.SourceTaskIDs)
	}
	if !strings.Contains(newTask.Goal, "前序探索记忆继承") {
		t.Fatalf("expected goal to mention inherited prior exploration memory, got %q", newTask.Goal)
	}
}

type mock409LimitProvider struct {
	mockDetailFirstProvider
	startCalls int
}

func (m *mock409LimitProvider) StartEnvironment(_ context.Context, id string) (*benchmark.EnvState, error) {
	m.startCalls++
	return nil, &benchmark.StructuredError{
		HTTPStatus: 409,
		Code:       "invalid_state",
		Message:    "max active challenge instances reached (3), please close an existing challenge",
	}
}

func TestBenchmarkTSecBench409InstanceLimitNoRetryBurn(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer m.Close()

	td := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx, m, td, td, td)

	sess, err := s.m.pg.CreateBenchmarkSession(t.Context(), db.BenchmarkSessionCreate{
		Name:          "tsecbench-409-cap-test",
		Provider:      "tsecbench",
		BaseURL:       "https://tsecbench.example",
		MaxConcurrent: 5,
		HintPolicy:    "never",
	})
	if err != nil {
		t.Fatalf("CreateBenchmarkSession: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = s.m.pg.DeleteBenchmarkSession(context.Background(), sess.ID)
	})

	if err := s.m.pg.SyncBenchmarkChallenges(t.Context(), sess.ID, []db.BenchmarkChallengeUpsert{
		{
			UniqueCode:      "ch-a",
			Title:           "ch-a",
			Description:     "Web A",
			Category:        "web",
			SubmissionType:  "flag",
			TotalScore:      100,
			FlagCount:       1,
			ContainerStatus: "stopped",
			Meta:            json.RawMessage(`{"has_container":true}`),
		},
		{
			UniqueCode:      "ch-b",
			Title:           "ch-b",
			Description:     "Web B",
			Category:        "web",
			SubmissionType:  "flag",
			TotalScore:      100,
			FlagCount:       1,
			ContainerStatus: "stopped",
			Meta:            json.RawMessage(`{"has_container":true}`),
		},
	}); err != nil {
		t.Fatalf("SyncBenchmarkChallenges: %v", err)
	}
	_ = s.m.pg.UpdateBenchmarkSessionStatus(t.Context(), sess.ID, "running", "")

	prov := &mock409LimitProvider{}
	rt := &benchSessionRuntime{
		sessionID:   sess.ID,
		prov:        prov,
		lastEnvPoll: map[string]time.Time{},
		taskStartAt: map[string]time.Time{},
	}
	if err := s.bench.tickSession(t.Context(), sess.ID, rt, 5); err != nil {
		t.Fatalf("tickSession: %v", err)
	}
	if rt.platformEnvCap != 3 {
		t.Fatalf("expected runtime platformEnvCap=3 learned from 409 message, got %d", rt.platformEnvCap)
	}
	if prov.startCalls != 1 {
		t.Fatalf("expected tickSession to stop launching after first 409 quota limit, got %d calls", prov.startCalls)
	}
	chA, _ := s.m.pg.GetBenchmarkChallenge(t.Context(), sess.ID, "ch-a")
	chB, _ := s.m.pg.GetBenchmarkChallenge(t.Context(), sess.ID, "ch-b")
	if chA.AutoRetryCount != 0 || chA.LastError != "" || chB.AutoRetryCount != 0 || chB.LastError != "" {
		t.Fatalf("409 instance limit must not burn auto_retry_count or stamp last_error: A=%+v B=%+v", chA, chB)
	}
}

type mockStagnantHintProvider struct {
	mockDetailFirstProvider
	hintCalls int
}

func (m *mockStagnantHintProvider) GetHint(_ context.Context, _ string) (string, error) {
	m.hintCalls++
	return "try PHP filter chain", nil
}

func TestBenchmarkEarlyStagnantHintAndHighScorePriority(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer m.Close()

	s := &Server{m: m}
	s.registerBenchmarkHooks()

	// Create bound task with 1 exhausted intent and 4 facts so both stagnation and high-score priority trigger.
	bt, err := m.CreateTaskWithOptions("[high] test", "goal", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "web"})
	if err != nil {
		t.Fatal(err)
	}
	defer m.DeleteTask(bt.ID, DeleteTaskOptions{})
	btID, _ := strconv.ParseInt(bt.ID, 10, 64)
	if _, err := bt.Store.AddNode("intent", map[string]any{"title": "dead path"}, 0, "exhausted", "planner", nil); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if _, err := bt.Store.AddNode("fact", map[string]any{"summary": fmt.Sprintf("fact %d", i)}, 0, "confirmed", "worker", nil); err != nil {
			t.Fatal(err)
		}
	}

	sess := &db.BenchmarkSession{
		ID:                  9901,
		HintPolicy:          "stagnant_only",
		PerChallengeTimeout: 3000, // 50m; earlyWindow = 20m
	}
	chHigh := &db.BenchmarkChallenge{
		ID:          1,
		SessionID:   sess.ID,
		UniqueCode:  "high",
		TotalScore:  1000,
		BoundTaskID: &btID,
		HintUsed:    false,
	}
	prov := &mockStagnantHintProvider{}
	rt := &benchSessionRuntime{
		sessionID:   sess.ID,
		prov:        prov,
		lastEnvPoll: map[string]time.Time{},
		taskStartAt: map[string]time.Time{"high": time.Now().Add(-15 * time.Minute)},
	}
	_ = s.bench.checkChallengeTimeoutAndHint(t.Context(), rt, sess, chHigh, true)
	if prov.hintCalls != 0 {
		t.Fatalf("expected no GetHint trigger before 20m earlyWindow, got %d calls", prov.hintCalls)
	}
	rt.taskStartAt["high"] = time.Now().Add(-21 * time.Minute)
	_ = s.bench.checkChallengeTimeoutAndHint(t.Context(), rt, sess, chHigh, true)
	if prov.hintCalls != 1 {
		t.Fatalf("expected early GetHint trigger at 21m with exhausted intent, got %d calls", prov.hintCalls)
	}

	// Verify pickChallengeQueue prioritizes high-score partial-progress round-2 retry ahead of untouched/low-score items.
	past := time.Now().Add(-1 * time.Second)
	if err := m.SetTaskStatus(bt.ID, "timeout"); err != nil {
		t.Fatal(err)
	}
	q := pickChallengeQueue([]*db.BenchmarkChallenge{
		{ID: 1, UniqueCode: "untouched", TotalScore: 200, Level: 1, AttemptCount: 0},
		{ID: 2, UniqueCode: "low-retry", TotalScore: 200, Level: 1, AttemptCount: 1, AutoRetryCount: 1, NextRetryAt: &past},
		{ID: 3, UniqueCode: "high-partial", TotalScore: 950, Level: 3, AttemptCount: 1, AutoRetryCount: 1, BoundTaskID: &btID, NextRetryAt: &past},
	}, m)
	if len(q) != 3 || q[0].UniqueCode != "high-partial" || q[1].UniqueCode != "untouched" || q[2].UniqueCode != "low-retry" {
		t.Fatalf("unexpected priority queue order: %+v", []string{q[0].UniqueCode, q[1].UniqueCode, q[2].UniqueCode})
	}
}

func TestPickChallengeQueueDifficultyOrdering(t *testing.T) {
	// 1. Challenges without difficulty tags (empty / auto / none, Level=0) keep original ID order without sorting.
	unlabeled := pickChallengeQueue([]*db.BenchmarkChallenge{
		{ID: 10, UniqueCode: "first-no-tag", Difficulty: "", Level: 0, TotalScore: 800},
		{ID: 20, UniqueCode: "second-auto", Difficulty: "auto", Level: 0, TotalScore: 100},
		{ID: 30, UniqueCode: "third-none", Difficulty: "none", Level: 0, TotalScore: 500},
	}, nil)
	if len(unlabeled) != 3 || unlabeled[0].UniqueCode != "first-no-tag" || unlabeled[1].UniqueCode != "second-auto" || unlabeled[2].UniqueCode != "third-none" {
		t.Fatalf("unlabeled challenges must preserve natural ID order without sorting, got %+v", []string{unlabeled[0].UniqueCode, unlabeled[1].UniqueCode, unlabeled[2].UniqueCode})
	}

	// 2. Challenges with text/composite/CJK/level difficulty labels run easiest -> hardest regardless of Level=0 or TotalScore.
	labeled := pickChallengeQueue([]*db.BenchmarkChallenge{
		{ID: 1, UniqueCode: "c-insane", Difficulty: "Insane", TotalScore: 1000},
		{ID: 2, UniqueCode: "c-hard", Difficulty: "困难(Web)", TotalScore: 900},
		{ID: 3, UniqueCode: "c-mid-hard", Difficulty: "medium-hard", TotalScore: 700},
		{ID: 4, UniqueCode: "c-medium", Difficulty: "中等", TotalScore: 500},
		{ID: 5, UniqueCode: "c-easy", Difficulty: "Easy", TotalScore: 300},
		{ID: 6, UniqueCode: "c-checkin", Difficulty: "Check-in", TotalScore: 100},
	}, nil)
	wantLabeled := []string{"c-checkin", "c-easy", "c-medium", "c-mid-hard", "c-hard", "c-insane"}
	for idx, want := range wantLabeled {
		if labeled[idx].UniqueCode != want {
			var gotCodes []string
			for _, ch := range labeled {
				gotCodes = append(gotCodes, ch.UniqueCode)
			}
			t.Fatalf("unexpected labeled order: want %v, got %v", wantLabeled, gotCodes)
		}
	}

	// 3. Mixed batch: easy/medium run before unlabeled (which keep relative ID order), hardest pushed last.
	mixed := pickChallengeQueue([]*db.BenchmarkChallenge{
		{ID: 1, UniqueCode: "m-hard", Difficulty: "Hard"},
		{ID: 2, UniqueCode: "m-nolabel-a", Difficulty: ""},
		{ID: 3, UniqueCode: "m-easy", Difficulty: "easy"},
		{ID: 4, UniqueCode: "m-nolabel-b", Difficulty: "auto"},
		{ID: 5, UniqueCode: "m-lv2", Difficulty: "Lv.2"},
		{ID: 6, UniqueCode: "m-lvl3", Difficulty: "", Level: 3},
	}, nil)
	wantMixed := []string{"m-easy", "m-lv2", "m-lvl3", "m-nolabel-a", "m-nolabel-b", "m-hard"}
	for idx, want := range wantMixed {
		if mixed[idx].UniqueCode != want {
			var gotCodes []string
			for _, ch := range mixed {
				gotCodes = append(gotCodes, ch.UniqueCode)
			}
			t.Fatalf("unexpected mixed difficulty order: want %v, got %v", wantMixed, gotCodes)
		}
	}
}

func TestIsRemoteSessionTerminatedError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "409 already finished",
			err:  &benchmark.StructuredError{HTTPStatus: 409, Code: "invalid_state", Message: "task task_202611l7cuoht9dx already finished"},
			want: true,
		},
		{
			name: "409 instance cap not terminal",
			err:  &benchmark.StructuredError{HTTPStatus: 409, Code: "invalid_state", Message: "max active challenge instances reached (3)"},
			want: false,
		},
		{
			name: "401 unauthorized",
			err:  &benchmark.StructuredError{HTTPStatus: 401, Message: "expired"},
			want: true,
		},
		{
			name: "ENDED code",
			err:  &benchmark.StructuredError{HTTPStatus: 400, Code: "ENDED", Message: "session ended"},
			want: true,
		},
	}
	for _, tc := range cases {
		if got := isRemoteSessionTerminatedError(tc.err); got != tc.want {
			t.Fatalf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestBenchmarkDeleteSessionCascadesTasksAndPreservesKitsAndTips(t *testing.T) {
	dataDir := t.TempDir()
	m, err := NewManager(dataDir, "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer m.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx, m, dataDir, dataDir, dataDir)
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}

	sess, err := s.m.pg.CreateBenchmarkSession(t.Context(), db.BenchmarkSessionCreate{
		Name:          "delete-cascade-test",
		Provider:      "tsecbench",
		BaseURL:       "https://tsecbench.example",
		MaxConcurrent: 1,
		HintPolicy:    "never",
	})
	if err != nil {
		t.Fatalf("CreateBenchmarkSession: %v", err)
	}
	t.Cleanup(func() {
		_ = s.m.pg.DeleteBenchmarkSession(context.Background(), sess.ID)
	})

	if err := s.m.pg.SyncBenchmarkChallenges(t.Context(), sess.ID, []db.BenchmarkChallengeUpsert{{
		UniqueCode:     "ch-del-1",
		Title:          "ch-del-1",
		Description:    "Web test",
		Category:       "web",
		SubmissionType: "flag",
		TotalScore:     100,
		FlagCount:      1,
	}}); err != nil {
		t.Fatal(err)
	}

	// Create 3 linked tasks: history-only (no benchmark_session_id), bound, and legacy session-linked.
	tHistory, err := s.m.CreateTaskWithOptions("hist-task", "goal", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "web"})
	if err != nil {
		t.Fatal(err)
	}
	tBound, err := s.m.CreateTaskWithOptions("bound-task", "goal", db.TaskCreateOptions{
		Name: "[ch-del-1] bound", Mode: "ctf", ChallengeType: "web", BenchmarkSessionID: &sess.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	tLegacy, err := s.m.CreateTaskWithOptions("legacy-task", "goal", db.TaskCreateOptions{
		Mode: "ctf", ChallengeType: "web", BenchmarkSessionID: &sess.ID,
	})
	if err != nil {
		t.Fatal(err)
	}

	histID, _ := strconv.ParseInt(tHistory.ID, 10, 64)
	boundID, _ := strconv.ParseInt(tBound.ID, 10, 64)
	legacyID, _ := strconv.ParseInt(tLegacy.ID, 10, 64)

	if err := s.m.pg.BindBenchmarkChallengeTask(t.Context(), sess.ID, "ch-del-1", histID); err != nil {
		t.Fatal(err)
	}
	if err := s.m.pg.BindBenchmarkChallengeTask(t.Context(), sess.ID, "ch-del-1", boundID); err != nil {
		t.Fatal(err)
	}

	// Create workspace file + legacy Kit (without pre-populated Content) + TipCard tied to tBound.
	ctfSvc := ctf.New(dataDir, s.m.pg)
	workDir := ctfSvc.EffectiveWorkDir(t.Context(), boundID, 0)
	if err := os.MkdirAll(workDir, 0750); err != nil {
		t.Fatal(err)
	}
	kitBody := "import requests\nprint('exploit ready')\n"
	if err := os.WriteFile(filepath.Join(workDir, "exp.py"), []byte(kitBody), 0640); err != nil {
		t.Fatal(err)
	}
	kit, err := s.m.pg.UpsertBoardKit(t.Context(), db.BoardKit{
		TaskID:   boundID,
		Name:     "exp.py",
		Path:     "/work/exp.py",
		Summary:  "preserved exploit script",
		Verified: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.m.pg.Exec(`DELETE FROM board_kits WHERE id=$1`, kit.ID) })

	tip, err := s.m.pg.CreateTipCard(t.Context(), db.TipCard{
		Category:     "web",
		Tags:         []string{"ssti"},
		Title:        "Survived Tip Card",
		Pitfall:      "Must survive benchmark deletion",
		SourceTaskID: &boundID,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.m.pg.DeleteTipCard(context.Background(), tip.ID) })

	req := httptest.NewRequest("DELETE", "/api/benchmarks/"+strconv.FormatInt(sess.ID, 10), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("DELETE benchmark %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Deleted      bool `json:"deleted"`
		DeletedTasks int  `json:"deleted_tasks"`
		FailedTasks  int  `json:"failed_tasks"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Deleted || resp.DeletedTasks != 3 || resp.FailedTasks != 0 {
		t.Fatalf("unexpected delete summary: %+v", resp)
	}

	for _, tid := range []int64{histID, boundID, legacyID} {
		row, err := s.m.pg.GetTask(tid)
		if err != nil || row != nil {
			t.Fatalf("expected task #%d deleted, got row=%+v err=%v", tid, row, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dataDir, "tasks", tBound.ID)); !os.IsNotExist(err) {
		t.Fatalf("expected task files directory removed after session delete, stat err=%v", err)
	}

	kits, err := s.m.pg.ListAllBoardKits(t.Context(), 100)
	if err != nil {
		t.Fatal(err)
	}
	var savedKit *db.BoardKit
	for i := range kits {
		if kits[i].ID == kit.ID {
			savedKit = &kits[i]
			break
		}
	}
	if savedKit == nil {
		t.Fatalf("expected kit #%d to survive benchmark session delete", kit.ID)
	}
	if savedKit.TaskID != 0 || savedKit.Content != kitBody || savedKit.SourceTaskName != "[ch-del-1] bound" {
		t.Fatalf("unexpected preserved kit snapshot: %+v", savedKit)
	}

	tips, err := s.m.pg.ListTips(t.Context(), "web", 100)
	if err != nil {
		t.Fatal(err)
	}
	foundTip := false
	for _, tc := range tips {
		if tc.ID == tip.ID {
			foundTip = true
			break
		}
	}
	if !foundTip {
		t.Fatalf("expected tip #%d to survive benchmark session delete", tip.ID)
	}
}
