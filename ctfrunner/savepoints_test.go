package ctfrunner

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEnsureSessionWithOptionsBindMountAndEnv(t *testing.T) {
	var created map[string]any
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/containers/"):
			w.WriteHeader(404)
			io.WriteString(w, `{"message":"no such container"}`)
		case r.Method == "POST" && r.URL.Path == "/containers/create":
			json.NewDecoder(r.Body).Decode(&created)
			io.WriteString(w, `{"Id":"cid-bind-1"}`)
		case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/volumes/create"):
			t.Fatalf("unexpected volume creation in bind-mount mode: %s", r.URL.Path)
		default:
			w.WriteHeader(204)
		}
	}))
	defer fake.Close()

	e := &Engine{Client: fake.Client(), Base: fake.URL, Image: "ctf-tools"}
	id, err := e.EnsureSessionWithOptions(t.Context(), SessionContainerOptions{
		Name:          "p3y-box-bind",
		Task:          "42",
		InputHash:     strings.Repeat("a", 64),
		HostWorkDir:   "/host/tasks/42/work",
		HostInputsDir: "/host/tasks/42/inputs",
		ExtraEnv: map[string]string{
			"HTTP_PROXY":  "http://host.docker.internal:8788",
			"HTTPS_PROXY": "http://host.docker.internal:8788",
			"NO_PROXY":    "127.0.0.1,localhost,.internal",
		},
	})
	if err != nil {
		t.Fatalf("EnsureSessionWithOptions: %v", err)
	}
	if id != "cid-bind-1" {
		t.Fatalf("got id=%q want cid-bind-1", id)
	}
	host := created["HostConfig"].(map[string]any)
	mounts := host["Mounts"].([]any)
	if len(mounts) != 2 {
		t.Fatalf("expected 2 bind mounts, got %d (%v)", len(mounts), mounts)
	}
	m0 := mounts[0].(map[string]any)
	m1 := mounts[1].(map[string]any)
	if m0["Type"] != "bind" || m0["Source"] != "/host/tasks/42/work" || m0["Target"] != "/work" {
		t.Fatalf("unexpected work mount: %v", m0)
	}
	if m1["Type"] != "bind" || m1["Source"] != "/host/tasks/42/inputs" || m1["Target"] != "/work/.inputs" || m1["ReadOnly"] != true {
		t.Fatalf("unexpected inputs mount: %v", m1)
	}
	envBytes, _ := json.Marshal(created["Env"])
	if !strings.Contains(string(envBytes), "HTTP_PROXY=http://host.docker.internal:8788") {
		t.Fatalf("missing proxy env: %s", envBytes)
	}
}

func TestSavepointAndRewindEndpoints(t *testing.T) {
	var cmds []string
	fakeDocker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/exec"):
			var req struct {
				Cmd []string `json:"Cmd"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			if len(req.Cmd) >= 3 {
				cmds = append(cmds, req.Cmd[2])
			}
			io.WriteString(w, `{"Id":"exec-1"}`)
		case r.Method == "POST" && r.URL.Path == "/exec/exec-1/start":
			w.WriteHeader(200)
		case r.Method == "GET" && r.URL.Path == "/exec/exec-1/json":
			if len(cmds) > 0 && strings.Contains(cmds[len(cmds)-1], "missing-sp") {
				io.WriteString(w, `{"Running":false,"ExitCode":44}`)
				return
			}
			io.WriteString(w, `{"Running":false,"ExitCode":0}`)
		default:
			w.WriteHeader(200)
		}
	}))
	defer fakeDocker.Close()

	stateDir := t.TempDir()
	spec := SessionSpec{TaskID: 7, IntentID: 11, InputHash: strings.Repeat("b", 64)}
	srv := &Server{
		Engine:   &Engine{Client: fakeDocker.Client(), Base: fakeDocker.URL, Image: "ctf-tools"},
		Token:    strings.Repeat("x", 24),
		StateDir: stateDir,
	}
	sess := &Session{Spec: spec, Name: "p3y-box-" + spec.Key(), ContainerID: "cid-7"}
	if err := srv.save(sess); err != nil {
		t.Fatal(err)
	}

	apiSrv := httptest.NewServer(srv.Handler())
	defer apiSrv.Close()
	client := &Client{URL: apiSrv.URL, Token: srv.Token}

	sp, err := client.CreateSavepoint(t.Context(), spec.Key(), "sp1")
	if err != nil {
		t.Fatalf("CreateSavepoint: %v", err)
	}
	if sp.ID != "sp1" || sp.Path != "/work/.snapshots/sp1" {
		t.Fatalf("unexpected savepoint: %+v", sp)
	}
	if len(cmds) != 1 || !strings.Contains(cmds[0], "cp -al") || !strings.Contains(cmds[0], "/work/.snapshots/sp1") {
		t.Fatalf("unexpected savepoint shell script: %v", cmds)
	}

	rw, err := client.Rewind(t.Context(), spec.Key(), "sp1")
	if err != nil {
		t.Fatalf("Rewind: %v", err)
	}
	if !rw.Rewound || rw.ID != "sp1" {
		t.Fatalf("unexpected rewind: %+v", rw)
	}
	if len(cmds) != 2 || !strings.Contains(cmds[1], "kill -TERM") || !strings.Contains(cmds[1], "cp -al") {
		t.Fatalf("unexpected rewind shell script: %v", cmds)
	}

	if _, err := client.Rewind(t.Context(), spec.Key(), "missing-sp"); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("expected 404 for missing savepoint, got %v", err)
	}
}
