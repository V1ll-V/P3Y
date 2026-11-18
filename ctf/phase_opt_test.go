package ctf

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildHTTPRaceProbeCommandValidationAndScript(t *testing.T) {
	if _, _, err := BuildHTTPRaceProbeCommand(HTTPRaceProbeSpec{URL: "ftp://example.com/redeem", Concurrency: 10}); err == nil {
		t.Fatal("expected invalid scheme error")
	}
	if _, _, err := BuildHTTPRaceProbeCommand(HTTPRaceProbeSpec{URL: "http://example.com/redeem", PreURL: "ftp://bad", Concurrency: 10}); err == nil {
		t.Fatal("expected invalid pre_url scheme error")
	}
	if _, _, err := BuildHTTPRaceProbeCommand(HTTPRaceProbeSpec{URL: "http://example.com/redeem", Method: "TRACE", Concurrency: 8}); err == nil {
		t.Fatal("expected disallowed method error")
	}

	cmd, timeout, err := BuildHTTPRaceProbeCommand(HTTPRaceProbeSpec{
		URL:            "https://target.internal:8443/api/redeem",
		PreURL:         "https://target.internal:8443/api/captcha",
		Headers:        map[string]string{"Authorization": "Bearer tok"},
		Cookies:        map[string]string{"sid": "abc"},
		Body:           `{"amount":100}`,
		Concurrency:    99, // clamped to 40
		TimeoutSeconds: 6,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(cmd, "python3 -c ") || timeout < 25 {
		t.Fatalf("unexpected command/timeout: %q timeout=%d", cmd, timeout)
	}
	const marker = "b64decode('"
	start := strings.Index(cmd, marker)
	if start < 0 {
		t.Fatalf("expected base64-encoded python script in command: %s", cmd)
	}
	rest := cmd[start+len(marker):]
	end := strings.Index(rest, "'")
	if end < 0 {
		t.Fatalf("unterminated b64decode string in command: %s", cmd)
	}
	pyBytes, err := base64.StdEncoding.DecodeString(rest[:end])
	if err != nil {
		t.Fatalf("decode embedded python script: %v", err)
	}
	py := string(pyBytes)
	if !strings.Contains(py, "threading.Barrier(") || !strings.Contains(py, "set_tunnel") {
		t.Fatalf("expected threading.Barrier and proxy set_tunnel in race probe script: %s", py)
	}
	fields := strings.Fields(cmd)
	rawCfg, err := base64.StdEncoding.DecodeString(strings.Trim(fields[len(fields)-1], "'\""))
	if err != nil {
		t.Fatalf("decode embedded config b64: %v", err)
	}
	var spec HTTPRaceProbeSpec
	if err := json.Unmarshal(rawCfg, &spec); err != nil {
		t.Fatalf("unmarshal embedded config: %v", err)
	}
	if spec.Method != "POST" || spec.Concurrency != 40 {
		t.Fatalf("expected defaulted Method=POST and clamped Concurrency=40, got %+v", spec)
	}
}
