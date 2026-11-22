package ctf

import (
	"sync"
	"testing"
)

// 验证真实的环境变量读取路径：P3Y_CTF_FLAG_PREFIXES -> flagRegexp -> ExtractFlags。
func TestExtractFlagsUsesEnvPrefixes(t *testing.T) {
	t.Setenv("P3Y_CTF_FLAG_PREFIXES", "hgame,DASCTF")
	flagOnce = sync.Once{}
	flagMatcher = nil
	t.Cleanup(func() { flagOnce = sync.Once{}; flagMatcher = nil })

	got := ExtractFlags("x hgame{a} y DASCTF{b} z other{c}", 10)
	if len(got) != 2 || got[0] != "hgame{a}" || got[1] != "DASCTF{b}" {
		t.Fatalf("got %v", got)
	}
}

func TestExtractFlagsFiltersRegexAndTruncatedPlaceholders(t *testing.T) {
	sample := `
		grep -oE 'flag{[a-zA-Z0-9_-]*}' out.txt
		re.findall(r'flag{[^}]+}', body)
		log excerpt: flag{fd7f...} and flag{abcd…}
		real1: flag{108d1174-c4d2-4c3d-8bd2-655ff64b30af}
		real2: flag{s0me_f1ag*with?sym!}
	`
	got := ExtractFlags(sample, 10)
	if len(got) != 2 {
		t.Fatalf("expected exactly 2 real flags, got %v", got)
	}
	if got[0] != "flag{108d1174-c4d2-4c3d-8bd2-655ff64b30af}" || got[1] != "flag{s0me_f1ag*with?sym!}" {
		t.Fatalf("unexpected extracted flags: %v", got)
	}
	if !IsSelfConstructedMockFlag("", "flag{[a-zA-Z0-9_-]*}") || !IsSelfConstructedMockFlag("", "flag{fd7f...}") {
		t.Fatal("expected IsSelfConstructedMockFlag to reject regex and truncated placeholders")
	}
}
