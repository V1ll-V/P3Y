package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"p3y/ctfrunner"
	"p3y/db"
)

func TestStage5ADAndTipsCrystallizeEndpoints(t *testing.T) {
	dsn := os.Getenv("P3Y_PG_DSN")
	if dsn == "" {
		t.Skip("postgres unavailable")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()

	task, err := pg.CreateTaskWithOptions("stage5-ad-api", "defend", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "web"})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)

	runnerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/sessions":
			var spec ctfrunner.SessionSpec
			_ = json.NewDecoder(r.Body).Decode(&spec)
			_ = json.NewEncoder(w).Encode(ctfrunner.Session{Spec: spec, ContainerID: "cid-s5", Name: "p3y-box-" + spec.Key(), InputsReady: true})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/exec"):
			var req struct {
				Command string `json:"command"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			if strings.Contains(req.Command, "exp.py") || strings.Contains(req.Command, "poc") {
				if strings.Contains(req.Command, "poc_blocked") {
					_ = json.NewEncoder(w).Encode(ctfrunner.Result{ExitCode: 1, Stderr: []byte("blocked")})
				} else {
					_ = json.NewEncoder(w).Encode(ctfrunner.Result{ExitCode: 0, Stdout: []byte("flag{ad_api_ok}")})
				}
			} else {
				_ = json.NewEncoder(w).Encode(ctfrunner.Result{ExitCode: 0, Stdout: []byte("sla ok")})
			}
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer runnerSrv.Close()

	t.Setenv("P3Y_BOX_URL", runnerSrv.URL)
	t.Setenv("P3Y_BOX_TOKEN", strings.Repeat("k", 24))
	t.Setenv("P3Y_BOX_BIND_MOUNT", "1")

	root := t.TempDir()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	tid := strconv.FormatInt(task.ID, 10)
	tObj := &Task{ID: tid, Mode: "ctf", Status: task.Status, Store: pg.Exploration(task.ExplorationID)}
	s := &Server{
		ctx: ctx,
		m:   &Manager{pg: pg, dir: root, tasks: map[string]*Task{tid: tObj}},
	}
	s.engine = NewEngine(s.m)
	_, err = s.m.pg.AddBoardItem(t.Context(), db.BoardItem{
		TaskID:   task.ID,
		Kind:     db.BoardKindSavepoint,
		Title:    "rce_verified",
		Summary:  "found template injection",
		Verified: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/tasks/"+tid+"/ad/weapons", strings.NewReader(`{"target_service":"web","script_path":"/work/exp.py","targets":["10.0.1.5:80"]}`))
	req.SetPathValue("id", tid)
	rec := httptest.NewRecorder()
	s.taskADWeaponCreate(rec, req)
	if rec.Code != 201 {
		t.Fatalf("create weapon status=%d body=%s", rec.Code, rec.Body.String())
	}

	// Run repeater
	req = httptest.NewRequest(http.MethodPost, "/api/tasks/"+tid+"/ad/repeater/run", strings.NewReader(`{}`))
	req.SetPathValue("id", tid)
	rec = httptest.NewRecorder()
	s.taskADRepeaterRun(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "flag{ad_api_ok}") {
		t.Fatalf("repeater status=%d body=%s", rec.Code, rec.Body.String())
	}

	// Run Catcher scan
	req = httptest.NewRequest(http.MethodPost, "/api/tasks/"+tid+"/ad/catcher/scan", strings.NewReader(`{"samples":[{"target":"127.0.0.1:80","request":"GET /?q=' UNION SELECT 1,2--"}]}`))
	req.SetPathValue("id", tid)
	rec = httptest.NewRecorder()
	s.taskADCatcherScan(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "sql_injection") {
		t.Fatalf("catcher status=%d body=%s", rec.Code, rec.Body.String())
	}

	// Run Patcher verify
	req = httptest.NewRequest(http.MethodPost, "/api/tasks/"+tid+"/ad/patcher/verify", strings.NewReader(`{"service_name":"web","check_cmd":"sla_ok","exploit_cmd":"poc_blocked"}`))
	req.SetPathValue("id", tid)
	rec = httptest.NewRecorder()
	s.taskADPatcherVerify(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"passed":true`) {
		t.Fatalf("patcher status=%d body=%s", rec.Code, rec.Body.String())
	}

	// Crystallize Tips
	req = httptest.NewRequest(http.MethodPost, "/api/tasks/"+tid+"/tips/crystallize", nil)
	req.SetPathValue("id", tid)
	rec = httptest.NewRecorder()
	s.taskTipsCrystallize(rec, req)
	if rec.Code != 200 {
		t.Fatalf("crystallize status=%d body=%s", rec.Code, rec.Body.String())
	}
	var cBody struct {
		Cards []db.TipCard `json:"cards"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &cBody)
	if len(cBody.Cards) == 0 {
		t.Fatalf("expected crystallized tip cards, got body=%s", rec.Body.String())
	}
	for _, c := range cBody.Cards {
		_ = pg.DeleteTipCard(t.Context(), c.ID)
	}
}
