package ctfrunner

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func emptyWorkTar(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestSharedWorkVolumeCreationAndSeededMarker(t *testing.T) {
	var (
		mu             sync.Mutex
		createdVolumes []map[string]any
		containerReqs  []map[string]any
	)
	docker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/json") && strings.HasPrefix(r.URL.Path, "/containers/"):
			w.WriteHeader(404)
		case r.Method == http.MethodPost && r.URL.Path == "/volumes/create":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			createdVolumes = append(createdVolumes, body)
			mu.Unlock()
			w.Write([]byte(`{"Name":"` + body["Name"].(string) + `"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/containers/create":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			containerReqs = append(containerReqs, body)
			mu.Unlock()
			w.Write([]byte(`{"Id":"cid-` + strings.TrimPrefix(r.URL.Query().Get("name"), "p3y-box-") + `"}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/start"):
			w.WriteHeader(204)
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/archive"):
			w.WriteHeader(200)
		default:
			w.WriteHeader(404)
		}
	}))
	defer docker.Close()

	// Note: GET /containers/{id}/json returns 200 on second call by inspecting id prefix.
	var dockerFull *httptest.Server
	dockerFull = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/containers/cid-") && strings.HasSuffix(r.URL.Path, "/json") {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"Id":"cid-test","Image":"img-1","State":{"Running":true},"Config":{"Labels":{"p3y.box.managed":"true"}}}`))
			return
		}
		docker.Config.Handler.ServeHTTP(w, r)
	}))
	defer dockerFull.Close()

	srv := &Server{
		Engine:   &Engine{Client: dockerFull.Client(), Base: dockerFull.URL, Image: "p3y/p3y-box-tools:test"},
		Token:    strings.Repeat("k", 24),
		StateDir: t.TempDir(),
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	cli := &Client{URL: ts.URL, Token: srv.Token}

	spec1 := SessionSpec{TaskID: 55, IntentID: 1, InputHash: strings.Repeat("a", 64), WorkVolume: "p3y-box-task-work-55"}
	sess1, err := cli.Prepare(t.Context(), spec1)
	if err != nil {
		t.Fatalf("Prepare intent 1: %v", err)
	}
	if sess1.WorkSeeded {
		t.Fatal("expected initial WorkSeeded=false before first upload")
	}

	// Upload work tar via PUT /work; must mark WorkVolume as seeded globally across intents/tasks.
	if err := cli.Upload(t.Context(), spec1.Key(), false, bytes.NewReader(emptyWorkTar(t))); err != nil {
		t.Fatalf("Upload work: %v", err)
	}

	spec2 := SessionSpec{TaskID: 55, IntentID: 2, InputHash: strings.Repeat("a", 64), WorkVolume: "p3y-box-task-work-55"}
	sess2, err := cli.Prepare(t.Context(), spec2)
	if err != nil {
		t.Fatalf("Prepare intent 2: %v", err)
	}
	if !sess2.WorkSeeded {
		t.Fatal("expected WorkSeeded=true on sibling intent sharing same WorkVolume")
	}

	specRetry := SessionSpec{TaskID: 88, IntentID: 1, InputHash: strings.Repeat("a", 64), WorkVolume: "p3y-box-task-work-55"}
	sessRetry, err := cli.Prepare(t.Context(), specRetry)
	if err != nil {
		t.Fatalf("Prepare retry task: %v", err)
	}
	if !sessRetry.WorkSeeded {
		t.Fatal("expected WorkSeeded=true on retry task inheriting WorkVolume")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(createdVolumes) != 3 {
		t.Fatalf("expected 3 volume ensures on shared volume, got %d", len(createdVolumes))
	}
	for i, cv := range createdVolumes {
		if cv["Name"] != "p3y-box-task-work-55" {
			t.Fatalf("call %d mounted volume %v, want p3y-box-task-work-55", i, cv["Name"])
		}
	}
	if len(containerReqs) != 3 {
		t.Fatalf("expected 3 distinct containers created, got %d", len(containerReqs))
	}
	labels, _ := containerReqs[1]["Labels"].(map[string]any)
	if labels["p3y.box.work_vol"] != "p3y-box-task-work-55" {
		t.Fatalf("expected p3y.box.work_vol label on shared volume container, got %v", labels)
	}
}
