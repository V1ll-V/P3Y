package intercept

import (
	"regexp"
	"testing"

	"p3y/db"
)

func TestMatchRulesForModeCTF(t *testing.T) {
	rules := []compiledRule{
		{
			InterceptRule: db.InterceptRule{ID: 1, Name: "[内置] 递归强制删除 rm -rf", MatchTarget: "tool_input", MatchType: "regex", Action: "deny", Enabled: true},
			re:            regexp.MustCompile(`(?i)\brm\b.{0,80}(?:-[a-z]*r[a-z]*f)`),
		},
		{
			InterceptRule: db.InterceptRule{ID: 2, Name: "[内置] 关机 / 重启", MatchTarget: "tool_input", MatchType: "regex", Action: "deny", Enabled: true},
			re:            regexp.MustCompile(`\b(?:reboot|shutdown)\b`),
		},
		{
			InterceptRule: db.InterceptRule{ID: 3, Name: "[内置] 破坏性系统命令", MatchTarget: "tool_input", MatchType: "regex", Action: "deny", Enabled: true},
			re:            regexp.MustCompile(`(?i)(?:\b(?:rm\s+-rf\s+/\*?(?:["'\s;&|]|$)|mkfs|dd\b[^|\n]{0,100}\bof=\s*/dev/[a-zA-Z])|:\(\)\s*\{)`),
		},
		{
			InterceptRule: db.InterceptRule{ID: 4, Name: "用户自定义禁止访问管理台", MatchTarget: "tool_input", MatchType: "string", Pattern: "/secret-admin", Action: "deny", Enabled: true},
		},
	}

	// Non-CTF (pentest / empty) still triggers built-in rm -rf and shutdown rules.
	if dec, ok := matchRulesForMode(rules, "pentest", "Bash", []byte(`{"command":"rm -rf /tmp/foo"}`)); !ok || dec.RuleID != 1 {
		t.Fatalf("pentest should match rm -rf built-in rule, got ok=%v dec=%+v", ok, dec)
	}
	if dec, ok := matchRulesForMode(rules, "", "Bash", []byte(`{"command":"reboot"}`)); !ok || dec.RuleID != 2 {
		t.Fatalf("default mode should match shutdown built-in rule, got ok=%v dec=%+v", ok, dec)
	}

	// CTF mode skips pentest-oriented built-in rules (rm -rf /tmp, shutdown/reboot keyword),
	// preserves container self-destruction safeguards (rm -rf /, dd of=/dev/sda),
	// and preserves user-defined rules.
	if dec, ok := matchRulesForMode(rules, "ctf", "Bash", []byte(`{"command":"cd /tmp && rm -rf cpy315"}`)); ok {
		t.Fatalf("ctf should allow local rm -rf /tmp, got blocked by %+v", dec)
	}
	if dec, ok := matchRulesForMode(rules, "ctf", "Bash", []byte(`{"command":"dd if=bzImage bs=1 skip=16057 > out/vmlinux"}`)); ok {
		t.Fatalf("ctf should allow dd image extraction, got blocked by %+v", dec)
	}
	if dec, ok := matchRulesForMode(rules, "ctf", "Bash", []byte(`{"command":"rm -rf /"}`)); !ok || dec.RuleID != 3 {
		t.Fatalf("ctf must still block rm -rf /, got ok=%v dec=%+v", ok, dec)
	}
	if dec, ok := matchRulesForMode(rules, "ctf", "Bash", []byte(`{"command":"curl http://target/secret-admin"}`)); !ok || dec.RuleID != 4 {
		t.Fatalf("ctf must still enforce user-defined rules, got ok=%v dec=%+v", ok, dec)
	}
}
