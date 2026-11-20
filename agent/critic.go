package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"p3y/db"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

const ctfCriticSystem = `【思考与输出语言规范】请全程使用简体中文进行简短犀利的反向证伪分析（专有术语与路径除外）。

你是 CTF 解题链路中的「挑刺员（Critic）」。主攻手（Solver）刚刚连续 3 次执行/利用尝试失败。你的唯一职责是做**反向证伪（Adversarial Falsification）**，绝不顺着沉没成本鼓励他“再微调一次偏移”。
请严格按以下 3 点在 350 字内输出（禁止寒暄）：
1. **最可能错误的核心前提**：指出主攻手哪一条隐含假设大概率是假的（例如：误判 glibc 版本/栈对齐 MOVAPS/截断或编码机制/缓冲与 EOF 时机/盲目猜测参数名/远程协议与本地差异）。
2. **最小对照证伪实验**：给出一个可立即用 1 个工具证实或推翻该假设的最小操作（如优先调用 diff_local_remote、http_fuzz_diff、py_repl 或 ctf_decompile 核查具体位置）。
3. **回滚/分叉建议**：若当前路径明显与死胡同高度相似，明确指令调用 board_rewind 回滚；若同一存档点已多次回滚，明确指令调用 plateau_fork 并发尝试多条备选路线。`

type criticFailureSample struct {
	Tool   string
	Input  string
	Output string
}

// CriticAdvisor generates a 1-turn falsification critique from a failure dossier.
type CriticAdvisor func(ctx context.Context, dossier string) (string, error)

type ctfCriticHooks struct {
	inner             harness.HookRunner
	pg                *db.DB
	taskID            int64
	intentID          int64
	threshold         int
	stagnantThreshold int
	advisor           CriticAdvisor
	emit              func(db.Activity)

	mu              sync.Mutex
	failures        []criticFailureSample
	stagnantSamples []criticFailureSample
	pendingCritique string
	critiqueCount   int
}

func newCTFCriticHooks(inner harness.HookRunner, prov llm.Provider, pg *db.DB, taskID, intentID int64, emit func(db.Activity)) *ctfCriticHooks {
	roleProv := withRoleThinking(prov, "critic", "", true)
	advisor := CriticAdvisor(func(ctx context.Context, dossier string) (string, error) {
		if roleProv == nil {
			return "", fmt.Errorf("no provider")
		}
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		if transcript.SessionIDFrom(cctx) == "" && taskID > 0 {
			cctx = transcript.WithSessionID(cctx, fmt.Sprintf("task%d-critic-i%d", taskID, intentID))
		}
		msg, _, _, err := roleProv.Complete(cctx, llm.CompletionRequest{
			System:    []string{ctfCriticSystem},
			MaxTokens: 700,
			Messages: []llm.Message{
				{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.TextBlock(dossier)}},
			},
		})
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(msg.Text()), nil
	})
	return &ctfCriticHooks{
		inner:             inner,
		pg:                pg,
		taskID:            taskID,
		intentID:          intentID,
		threshold:         3,
		stagnantThreshold: 10,
		advisor:           advisor,
		emit:              emit,
	}
}

func isCTFCriticMonitoredTool(name string) bool {
	switch name {
	case "Bash", "ctf_python", "ctf_gdb", "http_send", "ctf_http", "http_fuzz_diff", "http_race_probe",
		"py_repl", "ctf_probe_target", "ctf_session_send", "board_mark_savepoint":
		return true
	default:
		return false
	}
}

func classifyCTFToolFailure(name string, result []byte, isErr bool) (failed bool, reason string) {
	if isErr {
		return true, truncOutput(strings.TrimSpace(string(result)), 260)
	}
	raw := strings.TrimSpace(string(result))
	if raw == "" {
		return false, ""
	}
	var obj map[string]any
	if json.Unmarshal([]byte(raw), &obj) == nil {
		if errText, _ := obj["error"].(string); strings.TrimSpace(errText) != "" {
			return true, truncOutput(strings.TrimSpace(errText), 240)
		}
		if passed, ok := obj["passed"].(bool); ok && !passed {
			return true, "check passed=false"
		}
		if rc, ok := obj["exit_code"].(float64); ok && int(rc) != 0 {
			stderr := firstNonEmptyString(obj["stderr_excerpt"], obj["stderr"])
			stdout := firstNonEmptyString(obj["stdout_excerpt"], obj["stdout"])
			detail := strings.TrimSpace(stderr)
			if detail == "" {
				detail = strings.TrimSpace(stdout)
			}
			return true, fmt.Sprintf("exit=%d %s", int(rc), truncOutput(detail, 260))
		}
		// Check stdout/stderr inside JSON for crash/exception tracebacks even when wrapped by timeout/bash.
		for _, k := range []string{"stdout_excerpt", "stderr_excerpt", "stdout", "stderr"} {
			if s, _ := obj[k].(string); containsCTFFailureSignature(s) {
				return true, truncOutput(s, 260)
			}
		}
		return false, ""
	}
	if containsCTFFailureSignature(raw) {
		return true, truncOutput(raw, 260)
	}
	return false, ""
}

func firstNonEmptyString(vals ...any) string {
	for _, v := range vals {
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

// summarizeCriticToolOutput extracts actual exit_code/error/stdout/stderr from JSON tool
// responses instead of blindly truncating raw JSON metadata (which previously hid stdout
// behind id/task_id/command fields and caused Critic to hallucinate missing responses).
func summarizeCriticToolOutput(result []byte, maxLen int) string {
	raw := strings.TrimSpace(string(result))
	if raw == "" {
		return ""
	}
	var obj map[string]any
	if json.Unmarshal([]byte(raw), &obj) == nil {
		var parts []string
		if rc, ok := obj["exit_code"].(float64); ok {
			parts = append(parts, fmt.Sprintf("exit=%d", int(rc)))
		}
		if errText, _ := obj["error"].(string); strings.TrimSpace(errText) != "" {
			parts = append(parts, "error="+strings.TrimSpace(errText))
		}
		if out := strings.TrimSpace(firstNonEmptyString(obj["stdout"], obj["stdout_excerpt"])); out != "" {
			parts = append(parts, "stdout="+out)
		}
		if errOut := strings.TrimSpace(firstNonEmptyString(obj["stderr"], obj["stderr_excerpt"])); errOut != "" {
			parts = append(parts, "stderr="+errOut)
		}
		if len(parts) > 0 {
			return truncOutput(strings.Join(parts, " | "), maxLen)
		}
	}
	return truncOutput(raw, maxLen)
}

func containsCTFFailureSignature(s string) bool {
	if s == "" {
		return false
	}
	for _, marker := range []string{
		"Traceback (most recent call last)",
		"Segmentation fault",
		"stack smashing detected",
		"EOFError",
		"BrokenPipeError",
		"ConnectionRefusedError",
		"502 Bad Gateway",
		"Connection refused",
		"Failed to establish a new connection",
		"Operation timed out",
		"Connection timed out",
	} {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}

func (h *ctfCriticHooks) PreToolUse(ctx context.Context, name string, input []byte) (bool, string, []byte) {
	if h.inner != nil {
		if block, msg, mod := h.inner.PreToolUse(ctx, name, input); block {
			return block, msg, mod
		}
	}
	// Always allow pivot & progress-recording tools through without blocking;
	// only consume pendingCritique when actually injecting it to block a blind retry.
	allowPivot := name == "board_rewind" || name == "plateau_fork" || name == "diff_local_remote" ||
		name == "record_fact" || name == "board_record" || name == "board_mark_savepoint"
	if allowPivot {
		return false, "", nil
	}
	h.mu.Lock()
	critique := h.pendingCritique
	if critique != "" {
		h.pendingCritique = ""
	}
	h.mu.Unlock()
	if critique != "" {
		return true, critique, nil
	}
	return false, "", nil
}

func (h *ctfCriticHooks) PostToolUse(ctx context.Context, name string, input, result []byte, isErr bool) {
	if h.inner != nil {
		h.inner.PostToolUse(ctx, name, input, result, isErr)
	}
	if (name == "record_fact" || name == "board_record" || name == "board_mark_savepoint" ||
		name == "board_rewind" || name == "plateau_fork") && !isErr {
		h.mu.Lock()
		h.stagnantSamples = nil
		if name == "board_rewind" || name == "plateau_fork" {
			h.failures = nil
			h.pendingCritique = ""
		}
		h.mu.Unlock()
		return
	}
	if !isCTFCriticMonitoredTool(name) {
		return
	}
	sample := criticFailureSample{
		Tool:   name,
		Input:  truncOutput(strings.TrimSpace(string(input)), 260),
		Output: summarizeCriticToolOutput(result, 520),
	}
	failed, reason := classifyCTFToolFailure(name, result, isErr)

	var (
		snapshot   []criticFailureSample
		reasonKind string
	)
	h.mu.Lock()
	h.stagnantSamples = append(h.stagnantSamples, sample)
	if !failed {
		h.failures = nil
		if h.stagnantThreshold > 0 && len(h.stagnantSamples) >= h.stagnantThreshold {
			start := max(0, len(h.stagnantSamples)-4)
			snapshot = append([]criticFailureSample(nil), h.stagnantSamples[start:]...)
			h.stagnantSamples = nil
			h.critiqueCount++
			reasonKind = "停滞无新线索产出"
		}
	} else {
		sample.Output = reason
		h.failures = append(h.failures, sample)
		if len(h.failures) >= h.threshold {
			snapshot = append([]criticFailureSample(nil), h.failures...)
			h.failures = nil
			h.stagnantSamples = nil
			h.critiqueCount++
			reasonKind = "失败"
		}
	}
	roundNum := h.critiqueCount
	h.mu.Unlock()

	if len(snapshot) == 0 {
		return
	}

	dossier := h.buildDossier(ctx, snapshot)
	critiqueText := ""
	if h.advisor != nil {
		if txt, err := h.advisor(ctx, dossier); err == nil && strings.TrimSpace(txt) != "" {
			critiqueText = strings.TrimSpace(txt)
		}
	}
	if critiqueText == "" {
		critiqueText = fmt.Sprintf("连续执行出现%s：请暂停盲目微调或脚本循环试探，先假设当前核心前置判断有误（如路径/参数/偏移/编码/上游故障），优先调用 diff_local_remote、http_fuzz_diff、board_rewind 或记录关键结论后结束当前意图换向。", reasonKind)
	}
	formatted := fmt.Sprintf("【Critic 反向证伪提醒 #%d（%s触发；本次重复执行已拦截）】\n%s\n\n请先根据上述证伪结论核查前提、使用对照工具（diff_local_remote / http_fuzz_diff / py_repl）或调用 board_rewind / plateau_fork 调整路线；若确认外部服务不可用或无路可走请立即 record_fact 并结束当前意图。", roundNum, reasonKind, critiqueText)

	h.mu.Lock()
	h.pendingCritique = formatted
	h.mu.Unlock()

	if h.emit != nil {
		h.emit(db.Activity{
			Worker:  "critic",
			Kind:    "critic",
			Summary: fmt.Sprintf("Critic 触发第 %d 次反向证伪（%s）", roundNum, reasonKind),
			Detail:  truncOutput(critiqueText, 800),
		})
	}
}

func (h *ctfCriticHooks) Stop(ctx context.Context, messages []llm.Message) (bool, []string, string) {
	var (
		prevent  bool
		blocking []string
		msg      string
	)
	if h.inner != nil {
		prevent, blocking, msg = h.inner.Stop(ctx, messages)
	}
	if prevent || len(blocking) > 0 {
		return prevent, blocking, msg
	}
	h.mu.Lock()
	critique := h.pendingCritique
	if critique != "" {
		h.pendingCritique = ""
	}
	h.mu.Unlock()
	if critique != "" {
		return false, []string{critique}, ""
	}
	return false, nil, ""
}

func (h *ctfCriticHooks) buildDossier(ctx context.Context, samples []criticFailureSample) string {
	var b strings.Builder
	fmt.Fprintf(&b, "主攻手连续 %d 次调用失败记录：\n", len(samples))
	for i, s := range samples {
		fmt.Fprintf(&b, "[失败 #%d] tool=%s\n  input=%s\n  error/output=%s\n", i+1, s.Tool, s.Input, s.Output)
	}
	if h.pg != nil && h.taskID > 0 {
		if preRaw, err := h.pg.TaskPrecheck(ctx, h.taskID); err == nil && len(preRaw) > 0 {
			fmt.Fprintf(&b, "\nPhase-0 Precheck: %s\n", truncOutput(string(preRaw), 400))
		}
		if idx := h.pg.RenderBoardIndex(ctx, h.taskID); idx != "" {
			b.WriteString("\n")
			b.WriteString(idx)
		}
		if items, err := h.pg.ListBoardItems(ctx, h.taskID, db.BoardKindSavepoint); err == nil {
			for _, sp := range items {
				var meta map[string]any
				if json.Unmarshal(sp.Meta, &meta) == nil {
					if rc, ok := meta["rewind_count"].(float64); ok && int(rc) >= 2 {
						fmt.Fprintf(&b, "\n[注意] Savepoint #%d (%s) 已有 rewind_count=%d（处于停滞期，可建议 plateau_fork）。\n", sp.ID, sp.Title, int(rc))
					}
				}
			}
		}
	}
	return b.String()
}
