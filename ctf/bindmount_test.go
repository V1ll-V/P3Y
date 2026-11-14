package ctf

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"p3y/ctfrunner"
)

func TestServiceBindMountSkipsWorkTarAndControlEndpointsSkipPrepare(t *testing.T) {
	root := t.TempDir()
	var calls []string
	var lastSpec ctfrunner.SessionSpec

	runnerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "POST" && r.URL.Path == "/sessions":
			json.NewDecoder(r.Body).Decode(&lastSpec)
			json.NewEncoder(w).Encode(ctfrunner.Session{
				Spec:        lastSpec,
				ContainerID: "cid-1",
				Name:        "p3y-box-" + lastSpec.Key(),
				InputsReady: true,
			})
		case r.Method == "PUT" && strings.HasSuffix(r.URL.Path, "/work"):
			t.Fatalf("unexpected PUT /work in bind-mount mode: %s", r.URL.Path)
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/work"):
			t.Fatalf("unexpected GET /work in bind-mount mode: %s", r.URL.Path)
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/jobs"):
			w.Write([]byte(`[]`))
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/interactive"):
			w.Write([]byte(`[]`))
		case r.Method == "DELETE" && strings.Contains(r.URL.Path, "/jobs/"):
			w.WriteHeader(204)
		case r.Method == "DELETE" && strings.Contains(r.URL.Path, "/interactive/"):
			w.WriteHeader(204)
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/savepoints"):
			w.Write([]byte(`{"id":"sp1","path":"/work/.snapshots/sp1"}`))
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/rewind"):
			w.Write([]byte(`{"id":"sp1","rewound":true}`))
		default:
			w.WriteHeader(200)
			w.Write([]byte(`{}`))
		}
	}))
	defer runnerSrv.Close()

	svc := (&Service{
		Root:      root,
		BindMount: true,
		HostRoot:  "/host-data",
		Runner:    &ctfrunner.Client{URL: runnerSrv.URL, Token: strings.Repeat("k", 24)},
	}).WithProxy("127.0.0.1:8788", "")

	// Read/control endpoints must NOT trigger POST /sessions or PUT /work.
	if _, err := svc.ListJobs(t.Context(), 5, 9); err != nil {
		t.Fatalf("ListJobs: %v", err)
	}
	if err := svc.StopJob(t.Context(), 5, 9, "j1"); err != nil {
		t.Fatalf("StopJob: %v", err)
	}
	if _, err := svc.ListInteractive(t.Context(), 5, 9); err != nil {
		t.Fatalf("ListInteractive: %v", err)
	}
	if err := svc.CloseInteractive(t.Context(), 5, 9, "s1"); err != nil {
		t.Fatalf("CloseInteractive: %v", err)
	}
	for _, c := range calls {
		if strings.HasPrefix(c, "POST /sessions") || strings.Contains(c, "/work") {
			t.Fatalf("control call triggered unwanted prepare/upload: %s", c)
		}
	}

	// CreateSavepoint triggers POST /sessions with HostWorkDir & proxy Env (without PUT /work).
	work := svc.EffectiveWorkDir(t.Context(), 5, 9)
	if err := os.MkdirAll(work, 0700); err != nil {
		t.Fatal(err)
	}
	sp, err := svc.CreateSavepoint(t.Context(), 5, 9, "sp1")
	if err != nil {
		t.Fatalf("CreateSavepoint: %v", err)
	}
	if sp.ID != "sp1" {
		t.Fatalf("got savepoint %+v", sp)
	}
	expectedBind := filepath.Join("/host-data", "tasks", "5", "i9", "ctf-work")
	if lastSpec.HostWorkDir != expectedBind {
		t.Fatalf("HostWorkDir = %q, want %q", lastSpec.HostWorkDir, expectedBind)
	}
	if lastSpec.Env["HTTP_PROXY"] != "http://host.docker.internal:8788" || !strings.Contains(lastSpec.Env["NO_PROXY"], ".internal") {
		t.Fatalf("unexpected container proxy env: %v", lastSpec.Env)
	}
	rw, err := svc.Rewind(t.Context(), 5, 9, "sp1")
	if err != nil || !rw.Rewound {
		t.Fatalf("Rewind failed: rw=%+v err=%v", rw, err)
	}
}
