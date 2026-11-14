package ad

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"p3y/ctf"
	"p3y/ctfrunner"
	"p3y/db"
)

func TestADRepeaterCatcherPatcherAndLeadWorkflow(t *testing.T) {
	dsn := os.Getenv("P3Y_PG_DSN")
	if dsn == "" {
		t.Skip("test database required; set P3Y_PG_DSN")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()

	task, err := pg.CreateTaskWithOptions("stage5-ad-e2e", "attack and defend", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "web"})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)

	var (
		mu             sync.Mutex
		submittedFlags []string
		exploitBlocked bool
	)
	submitSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Flag string `json:"flag"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		submittedFlags = append(submittedFlags, body.Flag)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer submitSrv.Close()

	runnerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/sessions":
			var spec ctfrunner.SessionSpec
			_ = json.NewDecoder(r.Body).Decode(&spec)
			_ = json.NewEncoder(w).Encode(ctfrunner.Session{Spec: spec, ContainerID: "cid-ad", Name: "p3y-box-" + spec.Key(), InputsReady: true})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/exec"):
			var req struct {
				Command string `json:"command"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			switch {
			case strings.Contains(req.Command, "10.0.1.2"):
				_ = json.NewEncoder(w).Encode(ctfrunner.Result{ExitCode: 0, Stdout: []byte("flag{ad_round1_hit}\n")})
			case strings.Contains(req.Command, "10.0.2.2"):
				_ = json.NewEncoder(w).Encode(ctfrunner.Result{ExitCode: 1, Stderr: []byte("connection refused")})
			case strings.Contains(req.Command, "sla_check"):
				_ = json.NewEncoder(w).Encode(ctfrunner.Result{ExitCode: 0, Stdout: []byte("SLA OK")})
			case strings.Contains(req.Command, "apply_patch"):
				mu.Lock()
				exploitBlocked = true
				mu.Unlock()
				_ = json.NewEncoder(w).Encode(ctfrunner.Result{ExitCode: 0, Stdout: []byte("patched")})
			case strings.Contains(req.Command, "run_poc"):
				mu.Lock()
				blk := exploitBlocked
				mu.Unlock()
				if blk {
					_ = json.NewEncoder(w).Encode(ctfrunner.Result{ExitCode: 1, Stderr: []byte("403 forbidden")})
				} else {
					_ = json.NewEncoder(w).Encode(ctfrunner.Result{ExitCode: 0, Stdout: []byte("flag{own_box_leaked}")})
				}
			default:
				_ = json.NewEncoder(w).Encode(ctfrunner.Result{ExitCode: 0})
			}
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer runnerSrv.Close()

	root := t.TempDir()
	ctfSvc := &ctf.Service{
		Root:      root,
		DB:        pg,
		BindMount: true,
		Runner:    &ctfrunner.Client{URL: runnerSrv.URL, Token: strings.Repeat("k", 24)},
	}
	if err := ctfSvc.Sync(t.Context(), task.ID); err != nil {
		t.Fatal(err)
	}
	adSvc := &Service{DB: pg, CTF: ctfSvc, HTTP: submitSrv.Client()}

	// 1. Register weapon & trigger Repeater
	weapon, err := pg.CreateADWeapon(t.Context(), db.ADWeapon{
		TaskID:        task.ID,
		TargetService: "web-blog",
		ScriptPath:    "/work/exp_blog.py",
		Targets:       []string{"10.0.1.2:8080", "10.0.2.2:8080"},
		SubmitURL:     submitSrv.URL,
		SubmitToken:   "team-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	repRes, err := adSvc.RunRepeater(t.Context(), task.ID, weapon.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if repRes.TargetsHit != 1 || repRes.TargetsMiss != 1 || len(repRes.FlagsFound) != 1 || repRes.FlagsFound[0] != "flag{ad_round1_hit}" {
		t.Fatalf("unexpected repeater result: %+v", repRes)
	}
	mu.Lock()
	if len(submittedFlags) != 1 || submittedFlags[0] != "flag{ad_round1_hit}" {
		mu.Unlock()
		t.Fatalf("expected flag submitted to submit_url, got %v", submittedFlags)
	}
	mu.Unlock()

	// 2. Scan Catcher inbound anomaly samples
	catchRes, err := adSvc.ScanCatcher(t.Context(), task.ID, []CatcherSample{
		{Target: "web-blog:8080/render", Request: "POST /render\n\nname={{config.__class__.__init__.__globals__}}"},
		{Target: "web-blog:8080/ping", Request: "GET /ping?ip=127.0.0.1;cat /flag"},
	}, true)
	if err != nil || len(catchRes.Findings) < 2 {
		t.Fatalf("Catcher scan failed: res=%+v err=%v", catchRes, err)
	}

	// Overview before patching should surface Salvage + VerifyPatch recommendations.
	ov1, err := adSvc.Overview(t.Context(), task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ov1.Recommendations) < 2 {
		t.Fatalf("expected Lead recommendations after Catcher alerts, got %+v", ov1.Recommendations)
	}

	// 3. Verify Red-Blue Patcher: SLA OK + Exploit Blocked
	patchRes, err := adSvc.VerifyPatch(t.Context(), task.ID, PatchVerifySpec{
		ServiceName: "web-blog",
		PatchCmd:    "apply_patch",
		CheckCmd:    "sla_check",
		ExploitCmd:  "run_poc",
	})
	if err != nil || !patchRes.Passed || !patchRes.SLAPassed || !patchRes.ExploitBlocked {
		t.Fatalf("expected Red-Blue Patcher to pass cleanly, got %+v err=%v", patchRes, err)
	}
}
