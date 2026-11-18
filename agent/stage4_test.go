package agent

import (
	"context"
	"encoding/json"
	"iter"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"p3y/ctf"
	"p3y/ctfrunner"
	"p3y/db"
	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
)

type stage4ScriptedProvider struct {
	mu       sync.Mutex
	calls    int
	complete func(ctx context.Context, callIdx int, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error)
}

func (p *stage4ScriptedProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.mu.Lock()
	idx := p.calls
	p.calls++
	p.mu.Unlock()
	if p.complete != nil {
		return p.complete(ctx, idx, req)
	}
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("ok")}}, "end_turn", llm.Usage{}, nil
}

func (p *stage4ScriptedProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		msg, stop, _, err := p.Complete(ctx, req)
		if err != nil {
			yield(llm.StreamEvent{}, err)
			return
		}
		if txt := msg.Text(); txt != "" {
			if !yield(llm.StreamEvent{Type: llm.SETextDelta, Text: txt}, nil) {
				return
			}
		}
		yield(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: stop}, nil)
	}
}

func TestStage4ToolpacksAndPlannerStripping(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("test database required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()

	pwnTask, err := pg.CreateTaskWithOptions("stage4-pwn-pack", "flag", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "pwn"})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(pwnTask.ID)

	root := t.TempDir()
	ctx, base := ctfBase(t.Context(), root, pg.Exploration(pwnTask.ExplorationID), pwnTask.ID, 1, nil)
	tools, def, cleanup := AugmentTools(ctx, "worker", base)
	defer cleanup()

	mounted := map[string]bool{}
	for _, tl := range tools {
		mounted[tl.Name()] = true
	}
	for _, wantBase := range []string{"py_repl", "ask_helper", "plateau_fork", "diff_local_remote", "http_fuzz_diff"} {
		if !mounted[wantBase] {
			t.Fatalf("expected %s to be in built CTF tools", wantBase)
		}
	}
	deferred := map[string]bool{}
	for _, name := range def.Deferred {
		deferred[name] = true
	}
	if !deferred["http_fuzz_diff"] {
		t.Fatal("expected http_fuzz_diff to be deferred on pwn task")
	}
	if deferred["diff_local_remote"] || deferred["py_repl"] || deferred["ask_helper"] || deferred["plateau_fork"] {
		t.Fatalf("unexpected deferral of binary/base tools on pwn task: %v", def.Deferred)
	}

	// Planner stripping must exclude all new execution/orchestration worker tools.
	stripped := stripCTFPlannerBase(tools)
	for _, tl := range stripped {
		switch tl.Name() {
		case "http_fuzz_diff", "diff_local_remote", "py_repl", "ask_helper", "plateau_fork":
			t.Fatalf("expected %s to be stripped from CTF planner", tl.Name())
		}
	}
}

func TestStage4Critic3FailureHook(t *testing.T) {
	advisorCalls := 0
	var lastDossier string
	hooks := newCTFCriticHooks(nil, nil, nil, 0, 0, nil)
	hooks.advisor = func(_ context.Context, dossier string) (string, error) {
		advisorCalls++
		lastDossier = dossier
		return "核心假设伪证：偏移或换行符错误，请立刻用 diff_local_remote 验证。", nil
	}

	// Non-monitored inspection tools must not count as failures.
	hooks.PostToolUse(t.Context(), "Read", []byte(`{"path":"/work/exp.py"}`), []byte(`err`), true)
	if len(hooks.failures) != 0 {
		t.Fatal("passive read tool must not count toward failure streak")
	}

	failRes := []byte(`{"exit_code":1,"stderr_excerpt":"EOFError: got EOF"}`)
	hooks.PostToolUse(t.Context(), "ctf_python", []byte(`{"code":"exploit1"}`), failRes, false)
	hooks.PostToolUse(t.Context(), "ctf_python", []byte(`{"code":"exploit2"}`), failRes, false)
	if advisorCalls != 0 {
		t.Fatal("critic should not trigger before 3 consecutive failures")
	}
	hooks.PostToolUse(t.Context(), "Bash", []byte(`{"command":"python3 exp.py"}`), failRes, false)
	if advisorCalls != 1 {
		t.Fatalf("expected critic advisor to trigger once on 3rd failure, got %d", advisorCalls)
	}
	if !strings.Contains(lastDossier, "exploit1") || !strings.Contains(lastDossier, "python3 exp.py") {
		t.Fatalf("dossier missing failed steps: %s", lastDossier)
	}

	// Pivot tool diff_local_remote must NOT be blocked while critique stays pending for Stop/next blind retry.
	blockPivot, _, _ := hooks.PreToolUse(t.Context(), "diff_local_remote", []byte(`{}`))
	if blockPivot {
		t.Fatal("expected diff_local_remote pivot tool to bypass critic block")
	}

	// Next non-pivot tool must receive the blocking critique once.
	blockRetry, msg, _ := hooks.PreToolUse(t.Context(), "ctf_python", []byte(`{}`))
	if !blockRetry || !strings.Contains(msg, "Critic 反向证伪提醒 #1") {
		t.Fatalf("expected PreToolUse block with critique, got block=%v msg=%q", blockRetry, msg)
	}

	// Consumed once -> subsequent call allowed; success resets any accumulated failures.
	hooks.PostToolUse(t.Context(), "ctf_python", []byte(`{}`), failRes, false)
	hooks.PostToolUse(t.Context(), "ctf_python", []byte(`{}`), []byte(`{"exit_code":0,"stdout_excerpt":"ok"}`), false)
	hooks.PostToolUse(t.Context(), "ctf_python", []byte(`{}`), failRes, false)
	if advisorCalls != 1 {
		t.Fatalf("expected clean exit=0 to reset failure streak, advisorCalls=%d", advisorCalls)
	}

	// Trigger again and verify Stop hook delivers critique if solver attempts to stop instead of calling a tool.
	hooks.PostToolUse(t.Context(), "Bash", []byte(`{}`), failRes, false)
	hooks.PostToolUse(t.Context(), "Bash", []byte(`{}`), failRes, false)
	if advisorCalls != 2 {
		t.Fatalf("expected second critic intervention, got %d", advisorCalls)
	}
	prevent, blocking, _ := hooks.Stop(t.Context(), nil)
	if prevent || len(blocking) != 1 || !strings.Contains(blocking[0], "Critic 反向证伪提醒 #2") {
		t.Fatalf("expected Stop hook to inject critique continuation, got prevent=%v blocking=%v", prevent, blocking)
	}
}

func TestStage4CriticSoftFailureAndStagnation(t *testing.T) {
	advisorCalls := 0
	hooks := newCTFCriticHooks(nil, nil, nil, 0, 0, nil)
	hooks.advisor = func(_ context.Context, _ string) (string, error) {
		advisorCalls++
		return "不要继续死等 502 或吞错空转。", nil
	}

	// Soft failure inside exit=0 stdout must trigger after 3 occurrences.
	softFail := []byte(`{"exit_code":0,"stdout_excerpt":"HTTP/1.1 502 Bad Gateway"}`)
	hooks.PostToolUse(t.Context(), "Bash", []byte(`{"command":"curl -s target"}`), softFail, false)
	hooks.PostToolUse(t.Context(), "Bash", []byte(`{"command":"curl -s target"}`), softFail, false)
	hooks.PostToolUse(t.Context(), "Bash", []byte(`{"command":"curl -s target"}`), softFail, false)
	if advisorCalls != 1 {
		t.Fatalf("expected soft 502 failures to trigger critic, got advisorCalls=%d", advisorCalls)
	}
	if _, msg, _ := hooks.PreToolUse(t.Context(), "Bash", []byte(`{}`)); !strings.Contains(msg, "Critic 反向证伪提醒 #1") {
		t.Fatalf("expected PreToolUse critique after soft failures, got %q", msg)
	}

	// 9 clean calls + record_fact resets stagnation counter; 10 calls without fact triggers critic #2.
	okRes := []byte(`{"exit_code":0,"stdout_excerpt":"200 OK empty"}`)
	for i := 0; i < 9; i++ {
		hooks.PostToolUse(t.Context(), "ctf_http", []byte(`{}`), okRes, false)
	}
	hooks.PostToolUse(t.Context(), "record_fact", []byte(`{}`), []byte(`{"ok":true}`), false)
	if advisorCalls != 1 {
		t.Fatalf("expected no stagnation trigger before threshold after record_fact, got %d", advisorCalls)
	}
	for i := 0; i < 10; i++ {
		hooks.PostToolUse(t.Context(), "ctf_http", []byte(`{}`), okRes, false)
	}
	if advisorCalls != 2 {
		t.Fatalf("expected 10 monitored calls without fact/board progress to trigger critic #2, got %d", advisorCalls)
	}
}

func TestStage4AskHelperBoundedAndScoped(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("test database required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()

	task, err := pg.CreateTaskWithOptions("stage4-helper", "solve", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "pwn"})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)

	es := pg.Exploration(task.ExplorationID)
	var seenToolNames []string
	prov := &stage4ScriptedProvider{
		complete: func(_ context.Context, _ int, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
			for _, tdef := range req.Tools {
				seenToolNames = append(seenToolNames, tdef.Name)
			}
			return llm.Message{
				Role:    llm.RoleAssistant,
				Content: []llm.ContentBlock{llm.TextBlock("Helper 完成静态分析：vuln 存在 0x40 栈溢出。")},
			}, "end_turn", llm.Usage{}, nil
		},
	}
	w := &Worker{prov: prov, workDir: t.TempDir(), nonStreamingFn: func() bool { return true }}
	var activities []db.Activity
	res, err := w.runCTFHelper(t.Context(), pg.Assets(), es, task.ID, 1, t.TempDir(), func(a db.Activity) {
		activities = append(activities, a)
	}, CTFHelperRequest{
		Goal:      "分析 /work/chall 的栈偏移",
		FocusPath: "/work/chall",
		MaxTurns:  5,
	})
	if err != nil {
		t.Fatalf("runCTFHelper: %v", err)
	}
	if !strings.Contains(res.Summary, "0x40") || len(activities) < 2 {
		t.Fatalf("unexpected helper result or missing activity logs: res=%+v activities=%d", res, len(activities))
	}
	for _, forbidden := range []string{"ask_helper", "plateau_fork", "board_mark_savepoint", "board_rewind", "ctf_submit_flag", "ctf_submit_exploit_proof"} {
		for _, seen := range seenToolNames {
			if seen == forbidden {
				t.Fatalf("forbidden tool %q mounted in Helper session", forbidden)
			}
		}
	}

	// Also verify askHelperTool recursion guard.
	nestedCtx := context.WithValue(t.Context(), ctfHelperSubKey{}, true)
	tl := askHelperTool()
	out, err := tl.Call(nestedCtx, json.RawMessage(`{"goal":"nested"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if raw, _ := json.Marshal(out); !strings.Contains(string(raw), "禁止") && !strings.Contains(string(raw), "嵌套") {
		t.Fatalf("expected nested ask_helper rejection, got %s", raw)
	}
}

func TestStage4PlateauForkParallelBranchesAndRewindTrigger(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("test database required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()

	task, err := pg.CreateTaskWithOptions("stage4-fork", "flag", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "pwn"})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)

	var execMu sync.Mutex
	var execCmds []string
	var passCheck atomic.Bool
	loserChecked := make(chan struct{})
	var loserCheckedOnce sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/sessions":
			var spec ctfrunner.SessionSpec
			_ = json.NewDecoder(r.Body).Decode(&spec)
			_ = json.NewEncoder(w).Encode(ctfrunner.Session{Spec: spec, ContainerID: "cid-fork", Name: "p3y-box-" + spec.Key(), InputsReady: true})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/savepoints"):
			_ = json.NewEncoder(w).Encode(ctfrunner.SavepointResult{ID: "sp-stage4", Path: "/snapshots/sp-stage4"})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/rewind"):
			_ = json.NewEncoder(w).Encode(ctfrunner.RewindResult{ID: "sp-stage4", Rewound: true})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/exec"):
			var req struct {
				Command string `json:"command"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			execMu.Lock()
			execCmds = append(execCmds, req.Command)
			execMu.Unlock()
			rc := 0
			if strings.Contains(req.Command, "fail_check") {
				rc = 1
				loserCheckedOnce.Do(func() { close(loserChecked) })
			} else if strings.Contains(req.Command, "check_win") && !strings.Contains(req.Command, "/winner") {
				if !passCheck.Load() {
					rc = 1
				}
			}
			_ = json.NewEncoder(w).Encode(ctfrunner.Result{ExitCode: rc, Stdout: []byte("ok")})
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()

	t.Setenv("P3Y_BOX_URL", srv.URL)
	t.Setenv("P3Y_BOX_TOKEN", strings.Repeat("k", 24))
	t.Setenv("P3Y_BOX_BIND_MOUNT", "1")

	root := t.TempDir()
	svc := ctf.New(root, pg)
	if err := svc.Sync(t.Context(), task.ID); err != nil {
		t.Fatal(err)
	}

	// Create savepoint and rewind twice to confirm plateau_detected=true on 2nd rewind.
	tools := ctfBoardTools(svc, pg, task.ID, 1)
	byName := map[string]actool.CoreTool{}
	for _, tl := range tools {
		byName[tl.Name()] = tl
	}
	spRes, err := byName["board_mark_savepoint"].Call(t.Context(), json.RawMessage(`{"title":"leak_ok","summary":"got base","check_cmd":"true"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	var sp db.BoardItem
	_ = json.Unmarshal([]byte(spRes.Flatten()), &sp)

	for i := 1; i <= 2; i++ {
		rwRes, err := byName["board_rewind"].Call(t.Context(), json.RawMessage(`{"savepoint_id":`+jsonNumber(sp.ID)+`,"deadend_title":"attempt","deadend_reason":"failed"}`), nil)
		if err != nil {
			t.Fatal(err)
		}
		var body map[string]any
		_ = json.Unmarshal([]byte(rwRes.Flatten()), &body)
		plateau, _ := body["plateau_detected"].(bool)
		if (i == 1 && plateau) || (i == 2 && !plateau) {
			t.Fatalf("rewind #%d expected plateau_detected=%v, got %v", i, i == 2, plateau)
		}
	}

	// Run Plateau Fork across two branches: "loser" fails check_cmd, "winner" succeeds check_cmd.
	prov := &stage4ScriptedProvider{
		complete: func(ctx context.Context, _ int, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
			promptText := ""
			if len(req.Messages) > 0 {
				promptText = req.Messages[0].Text()
			}
			if strings.Contains(promptText, "winner") {
				select {
				case <-loserChecked:
				case <-ctx.Done():
					return llm.Message{}, "", llm.Usage{}, ctx.Err()
				}
			}
			return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("done")}}, "end_turn", llm.Usage{}, nil
		},
	}
	w := &Worker{prov: prov, workDir: root, nonStreamingFn: func() bool { return true }}
	forkRes, err := w.runCTFPlateauFork(t.Context(), pg.Assets(), pg.Exploration(task.ExplorationID), task.ID, 1, t.TempDir(), nil, CTFPlateauForkRequest{
		SavepointID: sp.ID,
		Branches: []CTFBranchSpec{
			{Name: "loser", Hypothesis: "try one gadget", CheckCmd: "fail_check"},
			{Name: "winner", Hypothesis: "try ret2system", CheckCmd: "check_win"},
		},
		MaxTurns: 4,
	})
	if err != nil {
		t.Fatalf("runCTFPlateauFork: %v", err)
	}
	if forkRes.Winner != "winner" || !forkRes.Promoted || forkRes.BoardFactID <= 0 {
		t.Fatalf("expected winner='winner' promoted & board fact recorded, got %+v", forkRes)
	}

	// Verify deadend recorded for loser and fact recorded for winner.
	items, err := pg.ListBoardItems(t.Context(), task.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	foundFact, foundLoserDeadend := false, false
	for _, it := range items {
		if it.Kind == db.BoardKindFact && strings.Contains(it.Title, "winner") {
			foundFact = true
		}
		if it.Kind == db.BoardKindDeadend && it.Title == "fork_loser_failed" && it.ParentID != nil && *it.ParentID == sp.ID {
			foundLoserDeadend = true
		}
	}
	if !foundFact || !foundLoserDeadend {
		t.Fatalf("expected board winner fact (%v) and loser deadend (%v), items=%+v", foundFact, foundLoserDeadend, items)
	}

	// Verify runner saw promotion command from winner branch back to /work.
	execMu.Lock()
	cmds := strings.Join(execCmds, "\n")
	execMu.Unlock()
	if !strings.Contains(cmds, "/work/.forks/") || !strings.Contains(cmds, "/winner") {
		t.Fatalf("expected fork workdir & promotion commands, got:\n%s", cmds)
	}
}

func TestCTFVPNStatusHookAndIsolatedHTTPPaths(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("test database required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()

	task, err := pg.CreateTaskWithOptions("vpn-oob-test", "http://10.0.128.10:8000", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "web"})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)

	ovpnCfg := "client\ndev tun\nproto udp\nremote 1.2.3.4 1194\n<ca>\nCA\n</ca>\n<cert>\nCERT\n</cert>\n<key>\nKEY\n</key>\n"
	if err := pg.SetTaskCTFVPN(t.Context(), task.ID, ovpnCfg, strings.Repeat("a", 64), "client.ovpn"); err != nil {
		t.Fatal(err)
	}

	oldHook := CTFVPNStatusHook
	defer func() { CTFVPNStatusHook = oldHook }()
	CTFVPNStatusHook = func(_ context.Context, tid int64, _ string) (string, string, string) {
		if tid == task.ID {
			return "tun0", "10.254.1.48/24", "1.2.3.4:1194"
		}
		return "", "", ""
	}

	ts := pg.Exploration(task.ExplorationID)
	rendered, err := taskInputContext(t.TempDir(), ts, task.ID, 1)
	if err != nil {
		t.Fatalf("taskInputContext: %v", err)
	}
	if !strings.Contains(rendered, "10.254.1.48") || !strings.Contains(rendered, "0.0.0.0:<端口>") || strings.Contains(rendered, "ctfy-callback") {
		t.Fatalf("expected real tun0 IP 10.254.1.48 & 0.0.0.0 callback hint without ctfy-callback, got:\n%s", rendered)
	}

	cmd, _, err := ctfHTTPCommand(map[string]json.RawMessage{
		"url": json.RawMessage(`"http://10.0.128.10:8000/"`),
	})
	if err != nil {
		t.Fatalf("ctfHTTPCommand: %v", err)
	}
	if !strings.Contains(cmd, "/tmp/.ctf-http/cookies") || !strings.Contains(cmd, "/tmp/.ctf-http/response-body.txt") {
		t.Fatalf("expected ctf_http transient files under /tmp/.ctf-http, got:\n%s", cmd)
	}
}
