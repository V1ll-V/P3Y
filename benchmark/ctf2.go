package benchmark

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"p3y/mcphttp"
)

// CTF2Client implements Provider against DASCTF / CTF2's Streamable HTTP MCP endpoint
// (/api/ai/v1/mcp), supporting both Competition and Practice workflows with built-in
// quota tracking, rate limiting, attachment downloads, confirmation=true injection, and note redaction.
type CTF2Client struct {
	mcpURL      string
	token       string
	headers     map[string]string
	insecureTLS bool
	cfg         SessionConfig

	mu      sync.Mutex
	client  *mcphttp.Client
	readTS  []time.Time
	writeTS []time.Time
	httpDL  *http.Client

	challengeIndex sync.Map // unique_code -> ChallengeSpec metadata cache
}

func NewCTF2Client(mcpURL, token string, cfg SessionConfig) *CTF2Client {
	u := strings.TrimSpace(mcpURL)
	if u == "" {
		u = "https://ctf2.dasctf.com/api/ai/v1/mcp"
	}
	headers := map[string]string{}
	for k, v := range cfg.CustomHeaders {
		headers[k] = v
	}
	if strings.TrimSpace(token) != "" {
		headers["Authorization"] = "Bearer " + strings.TrimSpace(token)
	}
	return &CTF2Client{
		mcpURL:      u,
		token:       strings.TrimSpace(token),
		headers:     headers,
		insecureTLS: cfg.InsecureTLS,
		cfg:         cfg,
		httpDL:      &http.Client{Timeout: 90 * time.Second, Transport: newIPv4FirstTransport()},
	}
}

func (c *CTF2Client) Kind() string { return "ctf2" }

func (c *CTF2Client) conn(ctx context.Context) (*mcphttp.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client != nil {
		return c.client, nil
	}
	cl, err := mcphttp.New(ctx, "ctf2", c.mcpURL, c.headers, c.insecureTLS)
	if err != nil {
		return nil, err
	}
	c.client = cl
	return cl, nil
}

func (c *CTF2Client) Close() {
	c.mu.Lock()
	cl := c.client
	c.client = nil
	c.mu.Unlock()
	if cl != nil {
		_ = cl.Close()
	}
}

// pace enforces CTF2 limits (120 read/min, 30 write/min) with headroom (90/24).
func (c *CTF2Client) pace(ctx context.Context, write bool) error {
	limit := 90
	if write {
		limit = 24
	}
	for {
		c.mu.Lock()
		now := time.Now()
		cutoff := now.Add(-time.Minute)
		buf := c.readTS
		if write {
			buf = c.writeTS
		}
		kept := buf[:0]
		for _, ts := range buf {
			if ts.After(cutoff) {
				kept = append(kept, ts)
			}
		}
		if len(kept) < limit {
			kept = append(kept, now)
			if write {
				c.writeTS = kept
			} else {
				c.readTS = kept
			}
			c.mu.Unlock()
			return nil
		}
		wait := kept[0].Add(time.Minute + 150*time.Millisecond).Sub(now)
		c.mu.Unlock()
		if wait <= 0 {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

func (c *CTF2Client) callTool(ctx context.Context, write bool, toolName string, args any) (string, error) {
	if err := c.pace(ctx, write); err != nil {
		return "", err
	}
	cl, err := c.conn(ctx)
	if err != nil {
		return "", err
	}
	raw, callErr := cl.Call(ctx, toolName, args)
	if callErr != nil {
		// Reconnect once if stale session error, or retry read-only calls once on transient transport errors.
		if strings.Contains(strings.ToLower(callErr.Error()), "session") || strings.Contains(callErr.Error(), "404") {
			c.Close()
			if cl2, err2 := c.conn(ctx); err2 == nil {
				raw, callErr = cl2.Call(ctx, toolName, args)
			}
		} else if !write && parseCTF2Error(raw, callErr) == nil {
			c.Close()
			select {
			case <-ctx.Done():
				return raw, ctx.Err()
			case <-time.After(400 * time.Millisecond):
			}
			if cl2, err2 := c.conn(ctx); err2 == nil {
				raw, callErr = cl2.Call(ctx, toolName, args)
			}
		}
	}
	if callErr != nil {
		if se := parseCTF2Error(raw, callErr); se != nil {
			return raw, se
		}
		return raw, callErr
	}
	return raw, nil
}

func parseCTF2Error(rawText string, fallback error) *StructuredError {
	var payload struct {
		Code         string `json:"code"`
		Message      string `json:"message"`
		Retryable    bool   `json:"retryable"`
		RetryAfterMs int    `json:"retry_after_ms"`
		Hint         string `json:"hint"`
	}
	trimmed := strings.TrimSpace(rawText)
	if trimmed != "" && strings.HasPrefix(trimmed, "{") {
		if json.Unmarshal([]byte(trimmed), &payload) == nil && (payload.Code != "" || payload.Message != "") {
			return &StructuredError{
				HTTPStatus:   400,
				Code:         strings.ToLower(strings.TrimSpace(payload.Code)),
				Message:      payload.Message,
				Retryable:    payload.Retryable,
				RetryAfterMs: payload.RetryAfterMs,
				Hint:         payload.Hint,
			}
		}
	}
	if fallback != nil {
		msg := fallback.Error()
		if idx := strings.Index(msg, "{"); idx >= 0 {
			if json.Unmarshal([]byte(msg[idx:]), &payload) == nil && payload.Code != "" {
				return &StructuredError{
					HTTPStatus:   400,
					Code:         strings.ToLower(strings.TrimSpace(payload.Code)),
					Message:      payload.Message,
					Retryable:    payload.Retryable,
					RetryAfterMs: payload.RetryAfterMs,
					Hint:         payload.Hint,
				}
			}
		}
	}
	return nil
}

func (c *CTF2Client) WhoAmI(ctx context.Context) (*AgentProfile, error) {
	raw, err := c.callTool(ctx, false, "ctf2_agent_whoami", map[string]any{})
	if err != nil {
		return nil, err
	}
	var m map[string]any
	_ = json.Unmarshal([]byte(raw), &m)
	agentObj, _ := m["agent"].(map[string]any)
	prof := &AgentProfile{
		MaxEnvironments:    1,
		CompetitionEnabled: anyBool(m["competition_enabled"]),
		AgentID:            firstNonEmpty(anyString(agentObj["id"]), anyString(m["agent_id"])),
		AgentName:          firstNonEmpty(anyString(agentObj["name"]), anyString(m["name"]), anyString(m["username"])),
		Raw:                m,
	}
	if quotas, ok := m["quotas"].(map[string]any); ok {
		if mx := anyInt(quotas["max_environments"]); mx > 0 {
			prof.MaxEnvironments = mx
		}
		if act := anyInt(quotas["active_environments"]); act > 0 {
			prof.ActiveEnvironments = act
		}
		if rpm := anyInt(quotas["read_per_minute"]); rpm > 0 {
			prof.ReadPerMin = rpm
		}
		if wpm := anyInt(quotas["write_per_minute"]); wpm > 0 {
			prof.WritePerMin = wpm
		}
	}
	if comps, ok := m["active_competitions"].([]any); ok {
		for _, comp := range comps {
			if cm, ok := comp.(map[string]any); ok {
				id := anyString(cm["id"])
				if id == "" {
					id = anyString(cm["competition_id"])
				}
				title := anyString(cm["title"])
				if title == "" {
					title = anyString(cm["name"])
				}
				if id != "" || title != "" {
					prof.ActiveCompetitions = append(prof.ActiveCompetitions, strings.TrimSpace(id+" "+title))
				}
			}
		}
	}
	return prof, nil
}

func (c *CTF2Client) ListChallenges(ctx context.Context, cfg SessionConfig) ([]ChallengeSpec, error) {
	source := strings.ToLower(strings.TrimSpace(cfg.Source))
	if source == "" {
		source = "auto"
	}
	// If competition_id specified or competition mode requested, pull competition challenges first
	if cfg.CompetitionID != "" && source != "practice" {
		if cfg.InviteCode != "" {
			_, _ = c.callTool(ctx, true, "ctf2_join_competition", map[string]any{
				"competition_id": cfg.CompetitionID,
				"invite_code":    cfg.InviteCode,
			})
		}
		return c.listCompetitionChallenges(ctx, cfg.CompetitionID, cfg.StageID)
	}

	var combined []ChallengeSpec
	seen := map[string]bool{}
	appendUnique := func(specs []ChallengeSpec) {
		for _, sp := range specs {
			if sp.UniqueCode == "" || seen[sp.UniqueCode] {
				continue
			}
			seen[sp.UniqueCode] = true
			c.challengeIndex.Store(sp.UniqueCode, sp)
			combined = append(combined, sp)
		}
	}

	args := map[string]any{"limit": 100}
	if source == "practice" || source == "competition" {
		args["source"] = source
	}
	raw, err := c.callTool(ctx, false, "ctf2_agent_next_challenges", args)
	var recTotal int
	if err == nil {
		items := c.parseChallengeList(raw)
		appendUnique(items)
		var meta struct {
			Total int `json:"total"`
		}
		_ = json.Unmarshal([]byte(raw), &meta)
		recTotal = meta.Total
	}
	if source == "competition" && len(combined) > 0 {
		return combined, nil
	}
	// When no recommendations returned OR recommendations appear paginated/truncated (< total),
	// inspect practice grounds with full pagination to pull the entire training ground catalog.
	if source != "competition" && (len(combined) == 0 || (recTotal > 0 && len(combined) < recTotal)) {
		gRaw, gErr := c.callTool(ctx, false, "ctf2_list_practice_grounds", map[string]any{})
		if gErr == nil {
			var gList []map[string]any
			if unmarshalFlexList(gRaw, &gList, "items", "practice_grounds", "grounds", "data") == nil && len(gList) > 0 {
				for _, g := range gList {
					pgID := firstNonEmpty(anyString(g["id"]), anyString(g["practice_ground_id"]))
					if pgID == "" {
						continue
					}
					for page := 1; page <= 20; page++ {
						cRaw, cErr := c.callTool(ctx, false, "ctf2_list_practice_challenges", map[string]any{
							"practice_ground_id": pgID,
							"unsolved_only":      true,
							"page":               page,
							"limit":              100,
						})
						if cErr != nil {
							break
						}
						var cs []map[string]any
						if unmarshalFlexList(cRaw, &cs, "items", "challenges", "data") != nil || len(cs) == 0 {
							break
						}
						batch := make([]ChallengeSpec, 0, len(cs))
						for _, item := range cs {
							batch = append(batch, mapCTF2Challenge(item, "", "", pgID))
						}
						appendUnique(batch)
						if !ctf2HasMorePages(cRaw, page, len(cs), 100) {
							break
						}
					}
				}
			}
		}
	}
	if len(combined) > 0 {
		return combined, nil
	}
	if err != nil {
		return nil, err
	}
	return []ChallengeSpec{}, nil
}

func ctf2HasMorePages(raw string, page, gotCount, limit int) bool {
	var pg struct {
		TotalPage int `json:"total_page"`
		Total     int `json:"total"`
		PageSize  int `json:"page_size"`
	}
	if json.Unmarshal([]byte(raw), &pg) == nil {
		if pg.TotalPage > 0 {
			return page < pg.TotalPage
		}
		if pg.Total > 0 && pg.PageSize > 0 {
			return page*pg.PageSize < pg.Total
		}
	}
	return gotCount >= limit
}

func (c *CTF2Client) listCompetitionChallenges(ctx context.Context, compID, stageID string) ([]ChallengeSpec, error) {
	stages := []string{}
	if stageID != "" {
		stages = append(stages, stageID)
	} else {
		rawComp, err := c.callTool(ctx, false, "ctf2_get_competition", map[string]any{"competition_id": compID})
		if err != nil {
			return nil, err
		}
		cm, err := unwrapCTF2Map(rawComp, "competition", "data")
		if err == nil {
			if arr, ok := cm["stages"].([]any); ok {
				for _, st := range arr {
					if sm, ok := st.(map[string]any); ok {
						sid := firstNonEmpty(anyString(sm["id"]), anyString(sm["stage_id"]))
						if sid != "" {
							stages = append(stages, sid)
						}
					}
				}
			}
		}
	}
	if len(stages) == 0 {
		stages = []string{""}
	}
	var out []ChallengeSpec
	for _, sid := range stages {
		for page := 1; page <= 20; page++ {
			args := map[string]any{
				"competition_id": compID,
				"page":           page,
				"limit":          100,
			}
			if sid != "" {
				args["stage_id"] = sid
			}
			raw, err := c.callTool(ctx, false, "ctf2_list_competition_challenges", args)
			if err != nil {
				return nil, err
			}
			var list []map[string]any
			_ = unmarshalFlexList(raw, &list, "items", "challenges", "data")
			if len(list) == 0 {
				break
			}
			for _, item := range list {
				spec := mapCTF2Challenge(item, compID, sid, "")
				c.challengeIndex.Store(spec.UniqueCode, spec)
				out = append(out, spec)
			}
			if !ctf2HasMorePages(raw, page, len(list), 100) {
				break
			}
		}
	}
	return out, nil
}

func (c *CTF2Client) parseChallengeList(raw string) []ChallengeSpec {
	var list []map[string]any
	if unmarshalFlexList(raw, &list, "items", "challenges", "data") != nil {
		return nil
	}
	out := make([]ChallengeSpec, 0, len(list))
	for _, item := range list {
		compID, stageID, pgID := "", "", ""
		if src, ok := item["source"].(map[string]any); ok {
			compID = anyString(src["competition_id"])
			stageID = anyString(src["stage_id"])
			pgID = anyString(src["practice_ground_id"])
		}
		if compID == "" {
			compID = anyString(item["competition_id"])
		}
		if stageID == "" {
			stageID = anyString(item["stage_id"])
		}
		if pgID == "" {
			pgID = anyString(item["practice_ground_id"])
		}
		spec := mapCTF2Challenge(item, compID, stageID, pgID)
		c.challengeIndex.Store(spec.UniqueCode, spec)
		out = append(out, spec)
	}
	return out
}

func mapCTF2Challenge(item map[string]any, compID, stageID, pgID string) ChallengeSpec {
	cid := firstNonEmpty(anyString(item["challenge_id"]), anyString(item["id"]))
	title := firstNonEmpty(anyString(item["title"]), anyString(item["name"]))
	desc := anyString(item["description"])
	cat := strings.TrimSpace(anyString(item["category"]))
	diff := anyString(item["difficulty"])
	score := firstNonZero(anyInt(item["score"]), anyInt(item["total_score"]), anyInt(item["points"]))
	cumScore := firstNonZero(anyInt(item["cumulative_score"]), anyInt(item["earned_points"]))
	subType := strings.ToLower(anyString(item["submission_type"]))
	if subType == "" {
		subType = "flag"
	}
	solved := anyBool(item["is_solved"]) || anyBool(item["solved"]) || anyBool(item["is_completed"])
	hasContainer := anyBool(item["has_container"]) || anyBool(item["container"])

	var files []AttachmentSpec
	if arr, ok := item["files"].([]any); ok {
		for _, f := range arr {
			if fm, ok := f.(map[string]any); ok {
				files = append(files, AttachmentSpec{
					ID:   firstNonEmpty(anyString(fm["file_id"]), anyString(fm["id"])),
					Name: firstNonEmpty(anyString(fm["file_name"]), anyString(fm["name"]), anyString(fm["filename"])),
					Kind: anyString(fm["kind"]),
					URL:  anyString(fm["url"]),
					Size: int64(anyInt(fm["size"])),
				})
			}
		}
	}
	var subFlags []SubFlagSpec
	if arr, ok := item["sub_flags"].([]any); ok {
		for _, sf := range arr {
			if sm, ok := sf.(map[string]any); ok {
				subFlags = append(subFlags, SubFlagSpec{
					ID:    anyString(sm["id"]),
					Title: firstNonEmpty(anyString(sm["title"]), anyString(sm["description"])),
					Score: firstNonZero(anyInt(sm["score"]), anyInt(sm["points"]), anyInt(sm["earned_points"])),
					Done:  anyBool(sm["is_solved"]) || anyBool(sm["solved"]),
				})
			}
		}
	}
	flagCount := firstNonZero(len(subFlags), anyInt(item["sub_flag_count"]), anyInt(item["total_sub_flag_count"]), anyInt(item["flag_count"]), 1)
	if len(subFlags) > 1 {
		subType = "suite"
	}
	correctFlags := 0
	for _, sf := range subFlags {
		if sf.Done {
			correctFlags++
		}
	}
	if correctFlags == 0 {
		correctFlags = anyInt(item["solved_sub_flag_count"])
	}
	if solved && correctFlags == 0 {
		correctFlags = flagCount
	}

	var choiceMeta *ChoiceMeta
	if cm, ok := item["choice"].(map[string]any); ok {
		ch := &ChoiceMeta{
			QuestionType: anyString(cm["question_type"]),
			AttemptsLeft: anyInt(cm["attempts_left"]),
			Locked:       anyBool(cm["locked"]),
		}
		if opts, ok := cm["options"].([]any); ok {
			for _, o := range opts {
				if om, ok := o.(map[string]any); ok {
					ch.Options = append(ch.Options, ChoiceOption{
						Label: anyString(om["label"]),
						Text:  anyString(om["text"]),
					})
				}
			}
		}
		choiceMeta = ch
		subType = "choice"
	}

	var ucode string
	if compID != "" {
		ucode = fmt.Sprintf("comp:%s:%s:%s", compID, stageID, cid)
	} else {
		ucode = fmt.Sprintf("prac:%s:%s", pgID, cid)
	}

	normCat := InferChallengeType(title, cat, desc)
	if normCat == "auto" && cat != "" {
		normCat = strings.ToLower(cat)
	}

	return ChallengeSpec{
		UniqueCode:          ucode,
		Title:               title,
		Description:         desc,
		Category:            normCat,
		Difficulty:          diff,
		SubmissionType:      subType,
		TotalScore:          score,
		CumulativeScore:     cumScore,
		FlagCount:           flagCount,
		CorrectFlagCount:    correctFlags,
		IsCompleted:         solved,
		ContainerStatus:     "stopped",
		HasContainer:        hasContainer,
		Files:               files,
		SubFlags:            subFlags,
		Choice:              choiceMeta,
		WindowState:         anyString(item["window_state"]),
		PersonalFilesStatus: anyString(item["personal_files_status"]),
		CompetitionID:       compID,
		StageID:             stageID,
		PracticeGroundID:    pgID,
		RawChallengeID:      cid,
	}
}

func (c *CTF2Client) resolveTarget(uniqueCode string) (compID, stageID, pgID, cid string) {
	if v, ok := c.challengeIndex.Load(uniqueCode); ok {
		sp := v.(ChallengeSpec)
		return sp.CompetitionID, sp.StageID, sp.PracticeGroundID, sp.RawChallengeID
	}
	parts := strings.Split(uniqueCode, ":")
	if len(parts) == 4 && parts[0] == "comp" {
		return parts[1], parts[2], "", parts[3]
	}
	if len(parts) == 3 && parts[0] == "prac" {
		return "", "", parts[1], parts[2]
	}
	return c.cfg.CompetitionID, c.cfg.StageID, "", uniqueCode
}

func (c *CTF2Client) GetChallengeDetail(ctx context.Context, uniqueCode string) (*ChallengeSpec, error) {
	compID, stageID, pgID, cid := c.resolveTarget(uniqueCode)
	var (
		raw string
		err error
	)
	if compID != "" {
		raw, err = c.callTool(ctx, false, "ctf2_get_competition_challenge", map[string]any{
			"competition_id": compID,
			"stage_id":       stageID,
			"challenge_id":   cid,
		})
	} else {
		raw, err = c.callTool(ctx, false, "ctf2_get_practice_challenge", map[string]any{
			"practice_ground_id": pgID,
			"challenge_id":       cid,
		})
	}
	if err != nil {
		return nil, err
	}
	m, err := unwrapCTF2Map(raw, "challenge", "data")
	if err != nil {
		return nil, err
	}
	spec := mapCTF2Challenge(m, compID, stageID, pgID)
	if spec.UniqueCode == "" || cid != "" {
		spec.UniqueCode = uniqueCode
	}
	c.challengeIndex.Store(spec.UniqueCode, spec)
	return &spec, nil
}

func (c *CTF2Client) DownloadAttachment(ctx context.Context, uniqueCode, fileID string) (string, []byte, error) {
	compID, stageID, pgID, cid := c.resolveTarget(uniqueCode)
	for attempt := 0; attempt < 2; attempt++ {
		var (
			raw string
			err error
		)
		if compID != "" {
			raw, err = c.callTool(ctx, false, "ctf2_get_competition_attachment_url", map[string]any{
				"competition_id": compID,
				"stage_id":       stageID,
				"challenge_id":   cid,
				"file_id":        fileID,
			})
		} else {
			raw, err = c.callTool(ctx, false, "ctf2_get_attachment_url", map[string]any{
				"practice_ground_id": pgID,
				"challenge_id":       cid,
				"file_id":            fileID,
			})
		}
		if err != nil {
			return "", nil, err
		}
		resp, err := unwrapCTF2Map(raw, "attachment", "data")
		if err != nil {
			return "", nil, err
		}
		dlURL := firstNonEmpty(anyString(resp["url"]), anyString(resp["download_url"]))
		fname := firstNonEmpty(anyString(resp["file_name"]), anyString(resp["filename"]), path.Base(dlURL))
		if dlURL == "" {
			return "", nil, errors.New("CTF2 未返回有效附件下载链接")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, dlURL, nil)
		if err != nil {
			return "", nil, err
		}
		httpResp, err := c.httpDL.Do(req)
		if err != nil {
			return "", nil, err
		}
		body, readErr := io.ReadAll(io.LimitReader(httpResp.Body, 64<<20))
		httpResp.Body.Close()
		if httpResp.StatusCode >= 200 && httpResp.StatusCode < 300 && readErr == nil {
			if fname == "" || fname == "." || fname == "/" {
				fname = "attachment_" + fileID
			}
			return fname, body, nil
		}
		if attempt == 0 && (httpResp.StatusCode == 401 || httpResp.StatusCode == 403 || httpResp.StatusCode == 410) {
			continue // retry signed url once on expiration
		}
		return "", nil, fmt.Errorf("下载附件失败 HTTP %d", httpResp.StatusCode)
	}
	return "", nil, errors.New("下载附件重试失败")
}

func (c *CTF2Client) StartEnvironment(ctx context.Context, uniqueCode string) (*EnvState, error) {
	compID, stageID, pgID, cid := c.resolveTarget(uniqueCode)
	var (
		raw string
		err error
	)
	if compID != "" {
		raw, err = c.callTool(ctx, true, "ctf2_start_competition_environment", map[string]any{
			"competition_id": compID,
			"stage_id":       stageID,
			"challenge_id":   cid,
		})
	} else {
		raw, err = c.callTool(ctx, true, "ctf2_start_challenge_environment", map[string]any{
			"practice_ground_id": pgID,
			"challenge_id":       cid,
		})
	}
	if err != nil {
		return nil, err
	}
	return parseCTF2Env(uniqueCode, raw), nil
}

func (c *CTF2Client) GetEnvironment(ctx context.Context, uniqueCode string) (*EnvState, error) {
	compID, stageID, pgID, cid := c.resolveTarget(uniqueCode)
	var (
		raw string
		err error
	)
	if compID != "" {
		raw, err = c.callTool(ctx, false, "ctf2_get_competition_environment", map[string]any{
			"competition_id": compID,
			"stage_id":       stageID,
			"challenge_id":   cid,
		})
	} else {
		raw, err = c.callTool(ctx, false, "ctf2_get_environment", map[string]any{
			"practice_ground_id": pgID,
			"challenge_id":       cid,
		})
	}
	if err != nil {
		return nil, err
	}
	return parseCTF2Env(uniqueCode, raw), nil
}

func (c *CTF2Client) ExtendEnvironment(ctx context.Context, uniqueCode string) (*EnvState, error) {
	compID, stageID, pgID, cid := c.resolveTarget(uniqueCode)
	var (
		raw string
		err error
	)
	if compID != "" {
		raw, err = c.callTool(ctx, true, "ctf2_extend_competition_environment", map[string]any{
			"competition_id": compID,
			"stage_id":       stageID,
			"challenge_id":   cid,
		})
	} else {
		raw, err = c.callTool(ctx, true, "ctf2_extend_environment", map[string]any{
			"practice_ground_id": pgID,
			"challenge_id":       cid,
		})
	}
	if err != nil {
		return nil, err
	}
	return parseCTF2Env(uniqueCode, raw), nil
}

func (c *CTF2Client) CloseEnvironment(ctx context.Context, uniqueCode string) error {
	compID, stageID, pgID, cid := c.resolveTarget(uniqueCode)
	if compID != "" {
		_, err := c.callTool(ctx, true, "ctf2_delete_competition_environment", map[string]any{
			"competition_id": compID,
			"stage_id":       stageID,
			"challenge_id":   cid,
		})
		return err
	}
	_, err := c.callTool(ctx, true, "ctf2_user_delete_practice_id_challenges_challengeid_environment", map[string]any{
		"practice_ground_id": pgID,
		"challenge_id":       cid,
	})
	return err
}

func parseCTF2Env(uniqueCode, raw string) *EnvState {
	m, err := unwrapCTF2Map(raw, "environment", "data")
	if err != nil {
		return &EnvState{UniqueCode: uniqueCode, Status: "pending"}
	}
	var addrs []string
	addAddr := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		for _, ex := range addrs {
			if ex == s {
				return
			}
		}
		addrs = append(addrs, s)
	}
	addAddr(anyString(m["access_url"]))
	if arr, ok := m["access_urls"].([]any); ok {
		for _, v := range arr {
			switch item := v.(type) {
			case string:
				addAddr(item)
			case map[string]any:
				addAddr(anyString(item["url"]))
			}
		}
	}
	ready := anyBool(m["access_ready"])
	lifecycleFailed := anyBool(m["lifecycle_failed"])
	status := strings.ToLower(strings.TrimSpace(anyString(m["status"])))
	switch {
	case lifecycleFailed || status == "failed" || status == "error":
		status = "failed"
	case status == "stopped" || status == "deleted" || status == "terminated":
		status = "stopped"
	case len(addrs) > 0 && (ready || status == "available" || status == "running" || status == "ready"):
		status = "available"
	default:
		status = "pending"
	}
	rem := anyInt(m["remaining_seconds"])
	var exp *time.Time
	if rawExp := strings.TrimSpace(anyString(m["expires_at"])); rawExp != "" {
		if parsed, perr := time.Parse(time.RFC3339Nano, rawExp); perr == nil {
			exp = &parsed
			if rem == 0 {
				if left := int(time.Until(parsed).Seconds()); left > 0 {
					rem = left
				}
			}
		}
	}
	if exp == nil && rem > 0 {
		t := time.Now().Add(time.Duration(rem) * time.Second)
		exp = &t
	}
	return &EnvState{
		UniqueCode:       uniqueCode,
		Status:           status,
		Addrs:            addrs,
		RemainingSeconds: rem,
		ExpiresAt:        exp,
	}
}

func (c *CTF2Client) SubmitAnswer(ctx context.Context, req SubmitRequest) (*SubmitResult, error) {
	compID, stageID, pgID, cid := c.resolveTarget(req.UniqueCode)
	args := map[string]any{
		"challenge_id": cid,
		"confirmation": true, // zero-interaction automated confirmation
	}
	if req.SubFlagID != "" {
		args["sub_flag_id"] = req.SubFlagID
	}
	if len(req.Choice) > 0 {
		args["choice"] = req.Choice
	} else {
		args["flag"] = strings.TrimSpace(req.Flag)
	}
	var (
		raw string
		err error
	)
	if compID != "" {
		args["competition_id"] = compID
		args["stage_id"] = stageID
		raw, err = c.callTool(ctx, true, "ctf2_submit_competition_flag", args)
	} else {
		args["practice_ground_id"] = pgID
		raw, err = c.callTool(ctx, true, "ctf2_submit_flag", args)
	}
	if err != nil {
		var se *StructuredError
		if errors.As(err, &se) {
			if se.Code == "already_solved" || se.Code == "duplicate" {
				return &SubmitResult{
					Correct:   true,
					Duplicate: true,
					Completed: true,
					Code:      se.Code,
					Message:   se.Message,
				}, nil
			}
			return &SubmitResult{
				Correct:      false,
				Code:         se.Code,
				Message:      se.Message,
				RetryAfterMs: se.RetryAfterMs,
				HTTPStatus:   se.HTTPStatus,
			}, err
		}
		return nil, err
	}
	var m map[string]any
	_ = json.Unmarshal([]byte(raw), &m)
	correct := anyBool(m["correct"]) || anyBool(m["accepted"]) || anyBool(m["is_solved"]) || strings.EqualFold(anyString(m["status"]), "correct")
	awarded := firstNonZero(anyInt(m["awarded"]), anyInt(m["score_awarded"]), anyInt(m["earned_points"]))
	if awarded == 0 && correct {
		awarded = anyInt(m["points"])
	}
	return &SubmitResult{
		Correct:          correct,
		Awarded:          awarded,
		CumulativeScore:  firstNonZero(anyInt(m["cumulative_score"]), anyInt(m["earned_points"])),
		CorrectFlagCount: firstNonZero(anyInt(m["correct_flag_count"]), anyInt(m["solved_sub_flag_count"])),
		TotalFlagCount:   firstNonZero(anyInt(m["total_flag_count"]), anyInt(m["total_sub_flag_count"])),
		Completed:        anyBool(m["challenge_solved"]) || anyBool(m["is_solved"]) || anyBool(m["is_completed"]),
		Message:          anyString(m["message"]),
		HTTPStatus:       200,
	}, nil
}

func (c *CTF2Client) GetHint(_ context.Context, _ string) (string, error) {
	return "", errors.New("CTF2 平台通过题目详情/规则指引提供线索，不支持单独 hint 接口")
}

func (c *CTF2Client) LogNote(ctx context.Context, uniqueCode, kind, content string) error {
	clean := RedactSensitive(content)
	if clean == "" {
		return nil
	}
	if len(clean) > 1900 {
		clean = clean[:1900] + "..."
	}
	compID, stageID, pgID, cid := c.resolveTarget(uniqueCode)
	args := map[string]any{
		"challenge_id": cid,
		"kind":         kind,
		"content":      clean,
	}
	if compID != "" {
		args["competition_id"] = compID
		args["stage_id"] = stageID
	} else if pgID != "" {
		args["practice_ground_id"] = pgID
	}
	_, err := c.callTool(ctx, true, "ctf2_agent_log_note", args)
	return err
}

func unmarshalFlexList(raw string, out *[]map[string]any, keys ...string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}
	if strings.HasPrefix(trimmed, "[") {
		return json.Unmarshal([]byte(trimmed), out)
	}
	var env map[string]json.RawMessage
	if err := json.Unmarshal([]byte(trimmed), &env); err != nil {
		return err
	}
	for _, k := range keys {
		if v, ok := env[k]; ok && len(v) > 0 {
			if json.Unmarshal(v, out) == nil {
				return nil
			}
		}
	}
	return nil
}

func anyString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatInt(int64(t), 10)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	default:
		return ""
	}
}

func anyInt(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case int64:
		return int(t)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(t))
		return n
	default:
		return 0
	}
}

func anyBool(v any) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	return false
}

func unwrapCTF2Map(raw string, keys ...string) (map[string]any, error) {
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, err
	}
	for _, k := range keys {
		if inner, ok := m[k].(map[string]any); ok {
			return inner, nil
		}
	}
	return m, nil
}

func firstNonZero(vals ...int) int {
	for _, v := range vals {
		if v != 0 {
			return v
		}
	}
	return 0
}
