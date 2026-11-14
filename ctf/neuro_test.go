package ctf

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"p3y/ctfrunner"
	"p3y/db"
)

func TestBuildHTTPFuzzDiffCommandValidation(t *testing.T) {
	if _, _, err := BuildHTTPFuzzDiffCommand(HTTPFuzzDiffSpec{URL: "ftp://x", Payloads: []string{"1"}}); err == nil {
		t.Fatal("expected invalid scheme error")
	}
	if _, _, err := BuildHTTPFuzzDiffCommand(HTTPFuzzDiffSpec{URL: "http://example.com/", Payloads: []string{"1"}}); err == nil {
		t.Fatal("expected error when neither {FUZZ} nor param specified")
	}
	tooMany := make([]string, 65)
	for i := range tooMany {
		tooMany[i] = "x"
	}
	if _, _, err := BuildHTTPFuzzDiffCommand(HTTPFuzzDiffSpec{URL: "http://example.com/?q={FUZZ}", Payloads: tooMany}); err == nil {
		t.Fatal("expected error for >64 payloads")
	}

	cmd, timeout, err := BuildHTTPFuzzDiffCommand(HTTPFuzzDiffSpec{
		URL:      "http://target.internal:8080/login",
		Method:   "POST",
		Param:    "user",
		Payloads: []string{"admin", "' OR 1=1--"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(cmd, "python3 -c ") || timeout < 30 {
		t.Fatalf("unexpected command/timeout: %q timeout=%d", cmd, timeout)
	}
}

func TestBuildDiffLocalRemoteCommandValidation(t *testing.T) {
	if _, _, err := BuildDiffLocalRemoteCommand(DiffLocalRemoteSpec{}); err == nil {
		t.Fatal("expected error when neither script_path nor commands supplied")
	}
	if _, _, err := BuildDiffLocalRemoteCommand(DiffLocalRemoteSpec{ScriptPath: "/etc/passwd"}); err == nil {
		t.Fatal("expected error for script_path outside /work")
	}
	cmd, timeout, err := BuildDiffLocalRemoteCommand(DiffLocalRemoteSpec{
		ScriptPath: "exp.py",
		LocalArgs:  []string{"LOCAL"},
		RemoteArgs: []string{"REMOTE"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(cmd, "python3 -c ") || timeout < 25 {
		t.Fatalf("unexpected command: %q timeout=%d", cmd, timeout)
	}
}

func TestEvalPyREPLAndForkWorkdirLifecycle(t *testing.T) {
	dsn := os.Getenv("P3Y_PG_DSN")
	if dsn == "" {
		t.Skip("test database required; set P3Y_PG_DSN")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()

	task, err := pg.CreateTaskWithOptions("stage4-neuro-repl", "solve", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "crypto"})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)

	var (
		mu          sync.Mutex
		calls       []string
		lastWrite   string
		readStage   int
		execCommands []string
	)
	runnerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "POST" && r.URL.Path == "/sessions":
			var spec ctfrunner.SessionSpec
			_ = json.NewDecoder(r.Body).Decode(&spec)
			_ = json.NewEncoder(w).Encode(ctfrunner.Session{Spec: spec, ContainerID: "cid-repl", Name: "p3y-box-" + spec.Key(), InputsReady: true})
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/interactive"):
			_, _ = w.Write([]byte(`[]`))
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/interactive"):
			var req map[string]string
			_ = json.NewDecoder(r.Body).Decode(&req)
			_ = json.NewEncoder(w).Encode(ctfrunner.InteractiveSessionInfo{ID: req["id"], Running: true})
		case r.Method == "POST" && strings.Contains(r.URL.Path, "/interactive/") && strings.HasSuffix(r.URL.Path, "/write"):
			var req struct {
				Data string `json:"data"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			mu.Lock()
			lastWrite = req.Data
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(ctfrunner.InteractiveWriteResult{BytesWritten: len(req.Data)})
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/interactive/") && strings.HasSuffix(r.URL.Path, "/read"):
			mu.Lock()
			st := readStage
			readStage++
			lw := lastWrite
			mu.Unlock()
			if st == 0 {
				_ = json.NewEncoder(w).Encode(ctfrunner.InteractiveReadResult{Output: "__P3Y_REPL_READY__\n", Offset: 20, Running: true})
				return
			}
			var msg struct {
				ID string `json:"id"`
			}
			_ = json.Unmarshal([]byte(lw), &msg)
			frame := "__P3Y_REPL_DONE__:" + msg.ID + `:` + `{"stdout":"ok\n","stderr":"","repr":"42","error":"","vars":{"x":"int=42"}}` + "\n"
			_ = json.NewEncoder(w).Encode(ctfrunner.InteractiveReadResult{Output: frame, Offset: 120, Running: true})
		case r.Method == "DELETE" && strings.Contains(r.URL.Path, "/interactive/"):
			w.WriteHeader(204)
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/exec"):
			var req struct {
				Command string `json:"command"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			mu.Lock()
			execCommands = append(execCommands, req.Command)
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(ctfrunner.Result{ExitCode: 0, Stdout: []byte("ok")})
		default:
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer runnerSrv.Close()

	svc := &Service{
		Root:      t.TempDir(),
		DB:        pg,
		BindMount: true,
		Runner:    &ctfrunner.Client{URL: runnerSrv.URL, Token: strings.Repeat("t", 24)},
	}

	res, err := svc.EvalPyREPL(t.Context(), task.ID, 22, "math", "x = 40 + 2\nx", false, 5)
	if err != nil {
		t.Fatalf("EvalPyREPL: %v", err)
	}
	if res.Repr != "42" || res.Vars["x"] != "int=42" || res.Session != "math" {
		t.Fatalf("unexpected REPL result: %+v", res)
	}

	dirs, err := svc.PrepareForkWorkdirs(t.Context(), task.ID, 22, "fork1", "sp-1", []string{"ret2libc", "srop"})
	if err != nil {
		t.Fatalf("PrepareForkWorkdirs: %v", err)
	}
	if dirs["ret2libc"] != "/work/.forks/fork1/ret2libc" || dirs["srop"] != "/work/.forks/fork1/srop" {
		t.Fatalf("unexpected branch dirs: %+v", dirs)
	}
	if err := svc.PromoteForkBranch(t.Context(), task.ID, 22, "fork1", "srop"); err != nil {
		t.Fatalf("PromoteForkBranch: %v", err)
	}
	mu.Lock()
	cmdsJoined := strings.Join(execCommands, "\n")
	mu.Unlock()
	if !strings.Contains(cmdsJoined, "/snapshots/sp-1") || !strings.Contains(cmdsJoined, "/work/.forks/fork1/srop") {
		t.Fatalf("expected snapshot copy & promotion commands, got:\n%s", cmdsJoined)
	}
}
