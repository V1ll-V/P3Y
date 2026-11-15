package benchmark

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRedactSensitive(t *testing.T) {
	in := "Found flag{secret_123} and DASCTF{abc_def} using Authorization: Bearer tok_super_secret_key_999"
	got := RedactSensitive(in)
	if strings.Contains(got, "secret_123") || strings.Contains(got, "abc_def") || strings.Contains(got, "tok_super_secret_key_999") {
		t.Fatalf("sensitive material leaked: %q", got)
	}
}

func TestParseSkillZip(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("ctf2-platform/SKILL.md")
	_, _ = w.Write([]byte("---\nname: ctf2-platform\ndescription: \"CTF2 skill\"\n---\n# Guide\nUse MCP tools.\n"))
	w2, _ := zw.Create("ctf2-platform/references/agent-play.md")
	_, _ = w2.Write([]byte("## Play Loop\nCall whoami first.\n"))
	_ = zw.Close()

	pkg, err := ParseSkillZip(buf.Bytes())
	if err != nil {
		t.Fatalf("ParseSkillZip failed: %v", err)
	}
	if pkg.Name != "ctf2-platform" {
		t.Fatalf("name = %q, want ctf2-platform", pkg.Name)
	}
	if !strings.Contains(pkg.Instructions, "Play Loop") {
		t.Fatalf("instructions missing agent-play.md: %q", pkg.Instructions)
	}
}

func TestTSecBenchClientFlowAndErrors(t *testing.T) {
	var submitted atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("BENCHMARK_TOKEN") != "tok-123" {
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"code":"task_not_found","message":"bad token"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/openapi/v1/challenges":
			_, _ = w.Write([]byte(`[{"unique_code":"web_sql_01","description":"sqli","difficulty":"easy","level":1,"total_score":100,"flag_count":2,"correct_flag_count":0,"is_completed":false,"container_status":"stopped","container_addr":[]}]`))
		case r.Method == http.MethodPost && r.URL.Path == "/openapi/v1/challenges/start":
			_, _ = w.Write([]byte(`{"unique_code":"web_sql_01","container_addr":["10.0.1.5:8080"]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/openapi/v1/challenges/submit":
			n := submitted.Add(1)
			if n == 2 {
				w.WriteHeader(409)
				_, _ = w.Write([]byte(`{"code":"duplicate","message":"already submitted"}`))
				return
			}
			_, _ = w.Write([]byte(`{"correct":true,"awarded":50,"cumulative_score":50,"correct_flag_count":1,"total_flag_count":2,"matched_flag_index":0}`))
		case r.Method == http.MethodPost && r.URL.Path == "/openapi/v1/challenges/close":
			_, _ = w.Write([]byte(`{"unique_code":"web_sql_01","closed":true}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	cl := NewTSecBenchClient(srv.URL, "tok-123")
	ctx := context.Background()
	list, err := cl.ListChallenges(ctx, SessionConfig{})
	if err != nil || len(list) != 1 || list[0].FlagCount != 2 {
		t.Fatalf("ListChallenges = %+v, err=%v", list, err)
	}
	env, err := cl.StartEnvironment(ctx, "web_sql_01")
	if err != nil || len(env.Addrs) != 1 || env.Addrs[0] != "10.0.1.5:8080" {
		t.Fatalf("StartEnvironment = %+v, err=%v", env, err)
	}
	res1, err := cl.SubmitAnswer(ctx, SubmitRequest{UniqueCode: "web_sql_01", Flag: "flag{1}"})
	if err != nil || !res1.Correct || res1.Awarded != 50 || res1.Completed {
		t.Fatalf("Submit 1 = %+v, err=%v", res1, err)
	}
	resDup, err := cl.SubmitAnswer(ctx, SubmitRequest{UniqueCode: "web_sql_01", Flag: "flag{1}"})
	if err != nil || !resDup.Duplicate || !resDup.Correct {
		t.Fatalf("Submit dup = %+v, err=%v", resDup, err)
	}
	if err := cl.CloseEnvironment(ctx, "web_sql_01"); err != nil {
		t.Fatalf("CloseEnvironment: %v", err)
	}
}

func TestCTF2MCPClientFlow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer agent-tok" {
			w.WriteHeader(401)
			return
		}
		var rpc struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      int             `json:"id"`
			Method  string          `json:"method"`
			Params  json.RawMessage `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&rpc)
		w.Header().Set("Content-Type", "application/json")
		switch rpc.Method {
		case "initialize":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + itoa(rpc.ID) + `,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"ctf2"}}}`))
		case "notifications/initialized":
			w.WriteHeader(202)
		case "tools/call":
			var call struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			}
			_ = json.Unmarshal(rpc.Params, &call)
			var payload any
			switch call.Name {
			case "ctf2_agent_whoami":
				payload = map[string]any{"name": "p3y-agent", "competition_enabled": true, "quotas": map[string]any{"max_environments": 2}}
			case "ctf2_agent_next_challenges":
				payload = []map[string]any{{"challenge_id": "ch99", "title": "Pwn Me", "category": "pwn", "score": 200, "has_container": true, "source": map[string]any{"practice_ground_id": "pg1"}}}
			case "ctf2_submit_flag":
				if call.Arguments["confirmation"] != true {
					_ = json.NewEncoder(w).Encode(map[string]any{
						"jsonrpc": "2.0", "id": rpc.ID,
						"result": map[string]any{
							"isError": true,
							"content": []map[string]string{{"type": "text", "text": `{"code":"invalid_request","message":"confirmation=true required"}`}},
						},
					})
					return
				}
				payload = map[string]any{"correct": true, "awarded": 200, "challenge_solved": true}
			case "ctf2_agent_log_note":
				if strings.Contains(call.Arguments["content"].(string), "secret_leak") {
					t.Fatalf("flag leaked into log_note: %v", call.Arguments["content"])
				}
				payload = map[string]any{"ok": true}
			}
			txt, _ := json.Marshal(payload)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      rpc.ID,
				"result": map[string]any{
					"content": []map[string]string{{"type": "text", "text": string(txt)}},
				},
			})
		}
	}))
	defer srv.Close()

	cl := NewCTF2Client(srv.URL, "agent-tok", SessionConfig{})
	defer cl.Close()
	ctx := context.Background()
	prof, err := cl.WhoAmI(ctx)
	if err != nil || prof.MaxEnvironments != 2 || !prof.CompetitionEnabled {
		t.Fatalf("WhoAmI = %+v, err=%v", prof, err)
	}
	chals, err := cl.ListChallenges(ctx, SessionConfig{})
	if err != nil || len(chals) != 1 || chals[0].UniqueCode != "prac:pg1:ch99" {
		t.Fatalf("ListChallenges = %+v, err=%v", chals, err)
	}
	res, err := cl.SubmitAnswer(ctx, SubmitRequest{UniqueCode: "prac:pg1:ch99", Flag: "flag{ok}"})
	if err != nil || !res.Correct || res.Awarded != 200 || !res.Completed {
		t.Fatalf("SubmitAnswer = %+v, err=%v", res, err)
	}
	if err := cl.LogNote(ctx, "prac:pg1:ch99", "finding", "Solved pwn and found flag{secret_leak}"); err != nil {
		t.Fatalf("LogNote: %v", err)
	}
}

func TestCTF2MCPWrappedSchemasAndAttachment(t *testing.T) {
	var attachmentServed atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/dl/chal.zip" {
			attachmentServed.Add(1)
			_, _ = w.Write([]byte("PK-TEST-ZIP"))
			return
		}
		var rpc struct {
			ID     int             `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&rpc)
		w.Header().Set("Content-Type", "application/json")
		switch rpc.Method {
		case "initialize":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + itoa(rpc.ID) + `,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"ctf2"}}}`))
		case "notifications/initialized":
			w.WriteHeader(202)
		case "tools/call":
			var call struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			}
			_ = json.Unmarshal(rpc.Params, &call)
			var payload any
			switch call.Name {
			case "ctf2_agent_whoami":
				payload = map[string]any{
					"agent":               map[string]any{"id": "ag-1", "name": "P3Y-Agent"},
					"competition_enabled": false,
					"quotas":              map[string]any{"max_environments": 1},
				}
			case "ctf2_get_practice_challenge":
				payload = map[string]any{
					"challenge": map[string]any{
						"id":                 "ch-1",
						"practice_ground_id": "pg-1",
						"name":               "unipickle",
						"description":        "Find the deserialization bug in /unpickle",
						"category":           "web",
						"difficulty":         "Easy",
						"points":             150,
						"has_container":      true,
						"files": []map[string]any{
							{"file_id": "file-1", "file_name": "app.py", "size": 11},
						},
					},
				}
			case "ctf2_get_attachment_url":
				payload = map[string]any{
					"attachment": map[string]any{
						"file_id":   "file-1",
						"file_name": "app.py",
						"url":       srv.URL + "/dl/chal.zip",
					},
				}
			case "ctf2_start_challenge_environment":
				payload = map[string]any{
					"environment": map[string]any{
						"access_ready": true,
						"status":       "running",
						"expires_at":   "2099-01-01T00:00:00Z",
						"access_urls": []map[string]any{
							{"type": "http", "url": "https://chal1.http-ctf2.example"},
						},
					},
				}
			case "ctf2_submit_flag":
				payload = map[string]any{
					"accepted":      true,
					"points":        150,
					"earned_points": 150,
					"is_solved":     true,
					"submission_id": "sub-1",
					"attempt":       1,
				}
			}
			txt, _ := json.Marshal(payload)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      rpc.ID,
				"result": map[string]any{
					"content": []map[string]string{{"type": "text", "text": string(txt)}},
				},
			})
		}
	}))
	defer srv.Close()

	cl := NewCTF2Client(srv.URL, "agent-tok", SessionConfig{})
	defer cl.Close()
	ctx := context.Background()

	prof, err := cl.WhoAmI(ctx)
	if err != nil || prof.AgentID != "ag-1" || prof.AgentName != "P3Y-Agent" || prof.MaxEnvironments != 1 {
		t.Fatalf("WhoAmI wrapped = %+v, err=%v", prof, err)
	}
	det, err := cl.GetChallengeDetail(ctx, "prac:pg-1:ch-1")
	if err != nil || det.Title != "unipickle" || det.Category != "web" || !det.HasContainer || !strings.Contains(det.Description, "deserialization") {
		t.Fatalf("GetChallengeDetail wrapped = %+v, err=%v", det, err)
	}
	if len(det.Files) != 1 || det.Files[0].ID != "file-1" || det.Files[0].Name != "app.py" {
		t.Fatalf("GetChallengeDetail files = %+v", det.Files)
	}
	fname, data, err := cl.DownloadAttachment(ctx, "prac:pg-1:ch-1", "file-1")
	if err != nil || fname != "app.py" || string(data) != "PK-TEST-ZIP" || attachmentServed.Load() != 1 {
		t.Fatalf("DownloadAttachment wrapped: fname=%q data=%q err=%v", fname, string(data), err)
	}
	env, err := cl.StartEnvironment(ctx, "prac:pg-1:ch-1")
	if err != nil || env.Status != "available" || len(env.Addrs) != 1 || env.Addrs[0] != "https://chal1.http-ctf2.example" || env.ExpiresAt == nil {
		t.Fatalf("StartEnvironment wrapped = %+v, err=%v", env, err)
	}
	sub, err := cl.SubmitAnswer(ctx, SubmitRequest{UniqueCode: "prac:pg-1:ch-1", Flag: "flag{ok}"})
	if err != nil || !sub.Correct || sub.Awarded != 150 || !sub.Completed {
		t.Fatalf("SubmitAnswer = %+v, err=%v", sub, err)
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
