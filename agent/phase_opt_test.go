package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"p3y/llmrec"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

func TestRoleThinkingProviderAndWireOverride(t *testing.T) {
	origHook := ThinkingOverride
	t.Cleanup(func() { ThinkingOverride = origHook })

	overrides := map[string][2]string{
		"worker_recon": {"disabled", ""},
		"critic":       {"enabled", "high"},
		"plateau_fork": {"enabled", "medium"},
	}
	ThinkingOverride = func(agentKey string) (string, string) {
		v := overrides[agentKey]
		return v[0], v[1]
	}

	var (
		mu       sync.Mutex
		captured []map[string]any
		paths    []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		mu.Lock()
		captured = append(captured, body)
		paths = append(paths, r.URL.Path)
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/messages"):
			_, _ = io.WriteString(w, `{"id":"m1","type":"message","role":"assistant","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`)
		case strings.HasSuffix(r.URL.Path, "/responses"):
			_, _ = io.WriteString(w, `{"status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"ok"}]}],"usage":{"input_tokens":1,"output_tokens":1}}`)
		default:
			_, _ = io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`)
		}
	}))
	defer srv.Close()

	makeBase := func(format llm.Format) llm.Provider {
		cfg := Config{
			Format:          format,
			BaseURL:         srv.URL,
			APIKey:          "test-key",
			Model:           "ds-flash",
			ThinkingType:    "enabled",
			ReasoningEffort: "high",
			MaxTokens:       1024,
			Stream:          false,
		}
		p, err := cfg.NewProvider()
		if err != nil {
			t.Fatalf("NewProvider(%v): %v", format, err)
		}
		return p
	}

	req := llm.CompletionRequest{
		MaxTokens: 512,
		Messages:  []llm.Message{llm.UserText("ping")},
	}
	ctx := transcript.WithSessionID(t.Context(), "test-thinking-sess")

	// 1. worker_recon on Anthropic must force thinking.type=disabled and clear output_config.
	reconAnt := withRoleThinking(makeBase(llm.FormatAnthropic), "worker_recon", "worker", true)
	if _, _, _, err := reconAnt.Complete(ctx, req); err != nil {
		t.Fatalf("recon Anthropic Complete: %v", err)
	}

	// 2. critic on OpenAI Chat Completions must preserve enabled + high effort.
	criticOAI := withRoleThinking(makeBase(llm.FormatOpenAI), "critic", "", true)
	if _, _, _, err := criticOAI.Complete(ctx, req); err != nil {
		t.Fatalf("critic OpenAI Complete: %v", err)
	}

	// 3. plateau_fork on OpenAI Responses must set reasoning.effort=medium.
	forkResp := withRoleThinking(makeBase(llm.FormatOpenAIResponses), "plateau_fork", "worker", true)
	if _, _, _, err := forkResp.Complete(ctx, req); err != nil {
		t.Fatalf("plateau_fork Responses Complete: %v", err)
	}

	// 4. Explicit req.Thinking="disabled" (e.g. compaction) must override critic's high thinking & suppress effort.
	disabledReq := req
	disabledReq.Thinking = "disabled"
	criticAnt := withRoleThinking(makeBase(llm.FormatAnthropic), "critic", "", true)
	if _, _, _, err := criticAnt.Complete(ctx, disabledReq); err != nil {
		t.Fatalf("explicit disabled Complete: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(captured) != 4 {
		t.Fatalf("expected 4 captured wire requests, got %d", len(captured))
	}

	// Check 1: Anthropic worker_recon
	if th, _ := captured[0]["thinking"].(map[string]any); th["type"] != "disabled" {
		t.Fatalf("expected worker_recon thinking.type=disabled on /messages, got %#v", captured[0])
	}
	if _, hasOC := captured[0]["output_config"]; hasOC {
		t.Fatalf("expected worker_recon disabled to omit output_config, got %#v", captured[0]["output_config"])
	}

	// Check 2: OpenAI critic
	if captured[1]["reasoning_effort"] != "high" {
		t.Fatalf("expected critic reasoning_effort=high on /chat/completions, got %#v", captured[1]["reasoning_effort"])
	}
	if th, _ := captured[1]["thinking"].(map[string]any); th["type"] != "enabled" {
		t.Fatalf("expected critic thinking.type=enabled on /chat/completions, got %#v", captured[1]["thinking"])
	}

	// Check 3: Responses plateau_fork
	if rsn, _ := captured[2]["reasoning"].(map[string]any); rsn["effort"] != "medium" {
		t.Fatalf("expected plateau_fork reasoning.effort=medium on /responses, got %#v", captured[2])
	}

	// Check 4: explicit req.Thinking="disabled" suppresses inherited output_config
	if th, _ := captured[3]["thinking"].(map[string]any); th["type"] != "disabled" {
		t.Fatalf("expected explicit disabled thinking.type=disabled, got %#v", captured[3])
	}
	if _, hasOC := captured[3]["output_config"]; hasOC {
		t.Fatalf("expected explicit disabled to omit output_config, got %#v", captured[3]["output_config"])
	}

	// Verify llmrec context helper sanity
	ovCtx := llmrec.WithThinkingOverride(context.Background(), "enabled", "low")
	ov := llmrec.ThinkingOverrideFrom(ovCtx)
	if ov.ThinkingType != "enabled" || ov.ReasoningEffort != "low" {
		t.Fatalf("unexpected llmrec override round-trip: ov=%+v", ov)
	}
}

func TestCTFRewindControllerJointSessionTruncation(t *testing.T) {
	snapDir := t.TempDir()
	const sessID = "rewind-unit-sess"
	ctrl := newCTFRewindController(nil, snapDir, sessID, nil, 0, nil)

	tools := []actool.CoreTool{
		writeTool("sp_mark", "mark savepoint", obj(nil), func(_ context.Context, _ json.RawMessage) (actool.Result, error) {
			ctrl.MarkSavepointPending(11)
			return actool.Text(`{"id":11,"saved":true}`), nil
		}),
		readTool("dead_probe", "explore failing direction", obj(nil), func(_ context.Context, _ json.RawMessage) (actool.Result, error) {
			return actool.Text("WRONG_NOISE_MARKER_FAIL: wrong gadget offset"), nil
		}),
		writeTool("sp_rewind", "rewind to savepoint", obj(nil), func(_ context.Context, _ json.RawMessage) (actool.Result, error) {
			ctrl.RequestRewind(11, "sp-clean", "bad-offset", "MOVAPS alignment crash", 1)
			return actool.Text(`{"rewound_to":11}`), nil
		}),
	}

	var seenBeforeRewind, seenAfterRewind []string
	prov := &stage4ScriptedProvider{
		complete: func(_ context.Context, idx int, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
			flatten := func(msgs []llm.Message) string {
				b, _ := json.Marshal(msgs)
				return string(b)
			}
			switch idx {
			case 0:
				return llm.Message{
					Role: llm.RoleAssistant,
					Content: []llm.ContentBlock{{
						Type:  llm.BlockToolUse,
						ID:    "call-sp",
						Name:  "sp_mark",
						Input: json.RawMessage(`{}`),
					}},
				}, "tool_use", llm.Usage{}, nil
			case 1:
				return llm.Message{
					Role: llm.RoleAssistant,
					Content: []llm.ContentBlock{{
						Type:  llm.BlockToolUse,
						ID:    "call-noise",
						Name:  "dead_probe",
						Input: json.RawMessage(`{}`),
					}},
				}, "tool_use", llm.Usage{}, nil
			case 2:
				seenBeforeRewind = append(seenBeforeRewind, flatten(req.Messages))
				return llm.Message{
					Role: llm.RoleAssistant,
					Content: []llm.ContentBlock{{
						Type:  llm.BlockToolUse,
						ID:    "call-rw",
						Name:  "sp_rewind",
						Input: json.RawMessage(`{}`),
					}},
				}, "tool_use", llm.Usage{}, nil
			default:
				seenAfterRewind = append(seenAfterRewind, flatten(req.Messages))
				return llm.Message{
					Role:    llm.RoleAssistant,
					Content: []llm.ContentBlock{llm.TextBlock("pivoted cleanly after rewind")},
				}, "end_turn", llm.Usage{}, nil
			}
		},
	}

	s := agentcore.NewSession(agentcore.Options{
		Provider:       prov,
		SessionID:      sessID,
		Tools:          tools,
		PermissionMode: permission.ModeBypass,
		MaxTurns:       8,
		NonStreaming:   true,
		Compactor:      wrapCompactorWithRewind(ctrl),
		Hooks:          ctfRewindHooks{ctrl: ctrl},
	})
	defer s.Close()

	ctx := withCTFRewindController(t.Context(), ctrl)
	for _, err := range s.Prompt(ctx, "solve target cleanly") {
		if err != nil {
			t.Fatalf("session prompt error: %v", err)
		}
	}

	if len(seenBeforeRewind) != 1 || !strings.Contains(seenBeforeRewind[0], "WRONG_NOISE_MARKER_FAIL") {
		t.Fatalf("expected pre-rewind context to contain failing noise, got %v", seenBeforeRewind)
	}
	if len(seenAfterRewind) != 1 {
		t.Fatalf("expected 1 post-rewind model call, got %d", len(seenAfterRewind))
	}
	after := seenAfterRewind[0]
	if strings.Contains(after, "WRONG_NOISE_MARKER_FAIL") {
		t.Fatalf("expected failed branch noise to be sliced out after rewind, got %s", after)
	}
	if !strings.Contains(after, "call-sp") || !strings.Contains(after, "MOVAPS alignment crash") {
		t.Fatalf("expected savepoint prefix + deadend notice after rewind, got %s", after)
	}

	apiMsgs := llm.MessagesForAPI(s.Messages())
	apiJSON, _ := json.Marshal(apiMsgs)
	if strings.Contains(string(apiJSON), "WRONG_NOISE_MARKER_FAIL") {
		t.Fatalf("expected session MessagesForAPI to exclude pruned dead-end branch, got %s", string(apiJSON))
	}

	// Disk snapshot must exist and reload in a fresh controller.
	diskPath := filepath.Join(snapDir, sessID+"-sp11.json")
	if _, err := os.Stat(diskPath); err != nil {
		t.Fatalf("expected disk snapshot %s: %v", diskPath, err)
	}
	reloaded := newCTFRewindController(nil, snapDir, sessID, nil, 0, nil)
	if got := reloaded.loadSnapshot(11); len(got) == 0 {
		t.Fatalf("expected fresh controller to reload savepoint #11 from disk")
	}
}

func TestBuildCTFGDBScript(t *testing.T) {
	script := buildCTFGDBScript("b main\nr\nquit\n")
	stateIdx := strings.Index(script, "[P3Y_GDB_STATE]")
	quitIdx := strings.LastIndex(script, "\nquit")
	if stateIdx < 0 || quitIdx < 0 {
		t.Fatalf("missing state block or trailing quit in gdb script: %s", script)
	}
	if stateIdx > quitIdx {
		t.Fatalf("expected [P3Y_GDB_STATE] collector to run BEFORE quit, got:\n%s", script)
	}
	if !strings.Contains(script, "16B_ALIGNED") || !strings.Contains(script, "disassemble") {
		t.Fatalf("expected 16B alignment check and disassembly in gdb script: %s", script)
	}
}

func TestRoleModelWireOverride(t *testing.T) {
	origHook := ThinkingOverride
	t.Cleanup(func() { ThinkingOverride = origHook })
	ThinkingOverride = nil

	var (
		mu     sync.Mutex
		models []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		m, _ := body["model"].(string)
		mu.Lock()
		models = append(models, m)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`)
	}))
	defer srv.Close()

	cfg := Config{
		Format:    llm.FormatOpenAI,
		BaseURL:   srv.URL,
		APIKey:    "test-key",
		Model:     "deepseek-flash",
		MaxTokens: 512,
		Stream:    false,
	}
	base, err := cfg.NewProvider()
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	req := llm.CompletionRequest{Messages: []llm.Message{llm.UserText("hi")}, MaxTokens: 32}

	// 1. Unset env -> all roles keep base model.
	t.Setenv("P3Y_LLM_REASONING_MODEL", "")
	t.Setenv("P3Y_LLM_PLANNER_MODEL", "")
	t.Setenv("P3Y_LLM_WORKER_MODEL", "")
	_, _, _, err = withRoleThinking(base, "planner", "", false).Complete(context.Background(), req)
	if err != nil {
		t.Fatalf("planner default: %v", err)
	}

	// 2. P3Y_LLM_REASONING_MODEL set -> planner/critic/plateau_fork escalate, worker stays fast,
	//    and explicit Thinking:"disabled" (compaction) stays fast!
	t.Setenv("P3Y_LLM_REASONING_MODEL", "deepseek-reasoner")
	_, _, _, err = withRoleThinking(base, "planner", "", false).Complete(context.Background(), req)
	if err != nil {
		t.Fatalf("planner reasoning: %v", err)
	}
	_, _, _, err = withRoleThinking(base, "critic", "", true).Complete(context.Background(), req)
	if err != nil {
		t.Fatalf("critic reasoning: %v", err)
	}
	_, _, _, err = withRoleThinking(base, "plateau_fork", "worker", true).Complete(context.Background(), req)
	if err != nil {
		t.Fatalf("plateau_fork reasoning: %v", err)
	}
	_, _, _, err = withRoleThinking(base, "worker", "", false).Complete(context.Background(), req)
	if err != nil {
		t.Fatalf("worker fast: %v", err)
	}
	compactReq := req
	compactReq.Thinking = "disabled"
	_, _, _, err = withRoleThinking(base, "planner", "", false).Complete(context.Background(), compactReq)
	if err != nil {
		t.Fatalf("planner compaction: %v", err)
	}

	// 3. Explicit per-role env overrides P3Y_LLM_REASONING_MODEL.
	t.Setenv("P3Y_LLM_PLANNER_MODEL", "deepseek-v4-pro")
	_, _, _, err = withRoleThinking(base, "planner", "", false).Complete(context.Background(), req)
	if err != nil {
		t.Fatalf("planner custom model: %v", err)
	}

	want := []string{
		"deepseek-flash",    // unset
		"deepseek-reasoner", // planner
		"deepseek-reasoner", // critic
		"deepseek-reasoner", // plateau_fork
		"deepseek-flash",    // worker
		"deepseek-flash",    // planner compaction (Thinking: disabled)
		"deepseek-v4-pro",   // planner explicit override
	}
	mu.Lock()
	defer mu.Unlock()
	if len(models) != len(want) {
		t.Fatalf("expected %d calls, got %d (%v)", len(want), len(models), models)
	}
	for i := range want {
		if models[i] != want[i] {
			t.Fatalf("call #%d: want model %q, got %q (all=%v)", i, want[i], models[i], models)
		}
	}
}
