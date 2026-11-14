package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"p3y/db"
)

func TestStage3BoardPrecheckKitsAndTipsEndpoints(t *testing.T) {
	pg := privateVerificationDB(t)
	root := t.TempDir()
	row, err := pg.CreateTaskWithOptions("api-stage3", "nc 10.1.2.3 1337", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "pwn"})
	if err != nil {
		t.Fatal(err)
	}
	task := &Task{ID: fmt.Sprint(row.ID), Mode: "ctf", Status: row.Status, Store: pg.Exploration(row.ExplorationID)}
	m := &Manager{pg: pg, dir: root, tasks: map[string]*Task{task.ID: task}}
	s := &Server{m: m, engine: NewEngine(m), ctx: t.Context()}

	// 1. POST /api/tasks/{id}/ctf/precheck
	r := httptest.NewRequest(http.MethodPost, "/api/tasks/"+task.ID+"/ctf/precheck", nil)
	r.SetPathValue("id", task.ID)
	w := httptest.NewRecorder()
	s.taskPrecheckRun(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "nc 10.1.2.3 1337") {
		t.Fatalf("precheck failed: code=%d body=%s", w.Code, w.Body.String())
	}

	// 2. GET /api/tasks/{id}/board & item detail
	r = httptest.NewRequest(http.MethodGet, "/api/tasks/"+task.ID+"/board", nil)
	r.SetPathValue("id", task.ID)
	w = httptest.NewRecorder()
	s.taskBoardGet(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Phase-0 Precheck 化验单") {
		t.Fatalf("board get failed: code=%d body=%s", w.Code, w.Body.String())
	}
	var boardResp struct {
		Items []db.BoardItem `json:"items"`
		Kits  []db.BoardKit  `json:"kits"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &boardResp)
	itemID := boardResp.Items[0].ID

	r = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/tasks/%s/board/items/%d", task.ID, itemID), nil)
	r.SetPathValue("id", task.ID)
	r.SetPathValue("itemID", strconv.FormatInt(itemID, 10))
	w = httptest.NewRecorder()
	s.taskBoardItemGet(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "nc 10.1.2.3 1337") {
		t.Fatalf("board item get failed: code=%d body=%s", w.Code, w.Body.String())
	}

	// 3. Global Kits
	if _, err := pg.UpsertBoardKit(t.Context(), db.BoardKit{TaskID: row.ID, Name: "exp.py", Path: "/work/exp.py", Summary: "final exp", Verified: true}); err != nil {
		t.Fatal(err)
	}
	r = httptest.NewRequest(http.MethodGet, "/api/kits?task_id="+task.ID, nil)
	w = httptest.NewRecorder()
	s.listGlobalKits(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "exp.py") {
		t.Fatalf("kits list failed: code=%d body=%s", w.Code, w.Body.String())
	}

	// 4. Tips Create / Search / Delete
	r = httptest.NewRequest(http.MethodPost, "/api/tips", strings.NewReader(`{"category":"pwn","tags":["seccomp","orw"],"title":"openat bypass","pitfall":"open blocked by seccomp, use openat"}`))
	w = httptest.NewRecorder()
	s.createTip(w, r)
	if w.Code != 201 {
		t.Fatalf("create tip failed: code=%d body=%s", w.Code, w.Body.String())
	}
	var created db.TipCard
	_ = json.Unmarshal(w.Body.Bytes(), &created)

	r = httptest.NewRequest(http.MethodGet, "/api/tips?category=pwn&tags=seccomp", nil)
	w = httptest.NewRecorder()
	s.listTips(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "openat bypass") {
		t.Fatalf("list tips failed: code=%d body=%s", w.Code, w.Body.String())
	}

	r = httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/tips/%d", created.ID), nil)
	r.SetPathValue("tipID", strconv.FormatInt(created.ID, 10))
	w = httptest.NewRecorder()
	s.deleteTip(w, r)
	if w.Code != 200 {
		t.Fatalf("delete tip failed: code=%d body=%s", w.Code, w.Body.String())
	}
}
