package agent

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"p3y/ctf"
	"p3y/ctfrunner"
	"p3y/db"
	actool "github.com/Autumn-27/norma/tool"
)

func TestBoardToolsSavepointRewindKitAndProgressiveDetail(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("test database required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()

	task, err := pg.CreateTaskWithOptions("stage3-agent-board", "find flag", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "pwn"})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)

	root := t.TempDir()
	svc := ctf.New(root, pg)
	svc.BindMount = true
	if err := svc.Sync(t.Context(), task.ID); err != nil {
		t.Fatal(err)
	}

	// Write a kit file in bind-mount shared workdir so SHA-256 can be computed deterministically.
	workDir := svc.EffectiveWorkDir(t.Context(), task.ID, 1)
	if err := os.MkdirAll(workDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "interact.py"), []byte("def menu(): return 1\n"), 0600); err != nil {
		t.Fatal(err)
	}

	checkPass := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/sessions":
			var spec ctfrunner.SessionSpec
			_ = json.NewDecoder(r.Body).Decode(&spec)
			_ = json.NewEncoder(w).Encode(ctfrunner.Session{Spec: spec, ContainerID: "cid-b", Name: "p3y-box-" + spec.Key(), InputsReady: true})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/exec"):
			code := 0
			out, errOut := "CHECK_OK", ""
			if !checkPass {
				code = 1
				out, errOut = "", "check failed"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"exit_code":  code,
				"stdout_b64": base64.StdEncoding.EncodeToString([]byte(out)),
				"stderr_b64": base64.StdEncoding.EncodeToString([]byte(errOut)),
			})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/savepoints"):
			var req struct {
				ID string `json:"id"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			_ = json.NewEncoder(w).Encode(ctfrunner.SavepointResult{ID: req.ID, Path: "/work/.snapshots/" + req.ID})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/rewind"):
			var req struct {
				ID string `json:"id"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			_ = json.NewEncoder(w).Encode(ctfrunner.RewindResult{ID: req.ID, Rewound: true})
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	svc.Runner = &ctfrunner.Client{URL: srv.URL, Token: strings.Repeat("k", 24)}

	toolsMap := map[string]actool.CoreTool{}
	for _, tl := range ctfBoardTools(svc, pg, task.ID, 1) {
		toolsMap[tl.Name()] = tl
	}
	if toolsMap["board_record"] != nil || toolsMap["board_read_detail"] != nil {
		t.Fatal("board_record and board_read_detail must not be exposed after blackboard unification")
	}

	// 1. Failing Check rejects Savepoint creation!
	checkPass = false
	failIn, _ := json.Marshal(map[string]any{"title": "bad", "summary": "bad sp", "check_cmd": "python3 /work/test.py"})
	res, err := toolsMap["board_mark_savepoint"].Call(t.Context(), failIn, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatalf("expected board_mark_savepoint to reject failing check_cmd, got: %v", res)
	}

	// 2. Passing Check creates Savepoint + Snapshot
	checkPass = true
	passIn, _ := json.Marshal(map[string]any{"title": "stage1 leak", "summary": "leaked libc", "detail": "LONG_L3_DETAIL_XYZ", "check_cmd": "python3 /work/leak.py", "snapshot_id": "sp-1"})
	res, err = toolsMap["board_mark_savepoint"].Call(t.Context(), passIn, nil)
	if err != nil || res.IsError {
		t.Fatalf("board_mark_savepoint failed: %+v err=%v", res, err)
	}
	var sp db.BoardItem
	_ = json.Unmarshal([]byte(res.Content[0].Text), &sp)
	if sp.ID <= 0 || !sp.Verified || sp.SnapshotID != "sp-1" {
		t.Fatalf("unexpected savepoint: %+v", sp)
	}

	// 3. Save Kit with Check Oracle + SHA256
	kitIn, _ := json.Marshal(map[string]any{"name": "interact.py", "summary": "pwntools menu wrapper", "check_cmd": "python3 -c 'import interact'", "savepoint_id": sp.ID})
	kRes, err := toolsMap["board_save_kit"].Call(t.Context(), kitIn, nil)
	if err != nil || kRes.IsError {
		t.Fatalf("board_save_kit failed: %+v err=%v", kRes, err)
	}
	var kit db.BoardKit
	_ = json.Unmarshal([]byte(kRes.Content[0].Text), &kit)
	if !kit.Verified || kit.SHA256 == "" {
		t.Fatalf("expected verified kit with sha256, got %+v", kit)
	}

	// 4. Rewind attaches Deadend & increments rewind_count
	rwIn, _ := json.Marshal(map[string]any{"savepoint_id": sp.ID, "deadend_title": "ret2dlresolve blocked", "deadend_reason": "FULL RELRO forbids GOT overwrite"})
	rwRes, err := toolsMap["board_rewind"].Call(t.Context(), rwIn, nil)
	if err != nil || rwRes.IsError {
		t.Fatalf("board_rewind failed: %+v err=%v", rwRes, err)
	}
	if !strings.Contains(rwRes.Content[0].Text, `"rewind_count":1`) {
		t.Fatalf("expected rewind_count=1, got %s", rwRes.Content[0].Text)
	}

	// 5. Progressive disclosure via DB store: RenderBoardIndex omits L3, GetBoardItem returns L3.
	digest := pg.RenderBoardIndex(t.Context(), task.ID)
	if !strings.Contains(digest, "stage1 leak") || !strings.Contains(digest, "[detail#") || strings.Contains(digest, "LONG_L3_DETAIL_XYZ") {
		t.Fatalf("unexpected RenderBoardIndex progressive disclosure: %s", digest)
	}
	stored, err := pg.GetBoardItem(t.Context(), task.ID, sp.ID)
	if err != nil || stored == nil || !strings.Contains(stored.Detail, "LONG_L3_DETAIL_XYZ") {
		t.Fatalf("expected L3 detail via pg.GetBoardItem, got %+v err=%v", stored, err)
	}
}
