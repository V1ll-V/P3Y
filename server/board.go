package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"p3y/db"
)

func (s *Server) taskOp(w http.ResponseWriter, r *http.Request) (*Task, int64, func(), bool) {
	t := s.m.ResolveTask(r.PathValue("id"))
	if t == nil {
		writeErr(w, 404, "任务不存在")
		return nil, 0, func() {}, false
	}
	if !s.engine.beginTaskOperation(t.ID) {
		writeErr(w, 409, "任务正在删除或归档")
		return nil, 0, func() {}, false
	}
	id, _ := strconv.ParseInt(t.ID, 10, 64)
	return t, id, func() { s.engine.decInflight(t.ID) }, true
}

func (s *Server) taskPrecheckGet(w http.ResponseWriter, r *http.Request) {
	t, id, done, ok := s.taskOp(w, r)
	if !ok {
		return
	}
	defer done()
	if !db.IsSandboxTaskMode(t.Mode) {
		writeErr(w, 400, "仅 CTF / AD 任务支持 Phase-0 Precheck")
		return
	}
	res, err := s.ctfService().RunPrecheck(r.Context(), id, false)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, res)
}

func (s *Server) taskPrecheckRun(w http.ResponseWriter, r *http.Request) {
	t, id, done, ok := s.taskOp(w, r)
	if !ok {
		return
	}
	defer done()
	if !db.IsSandboxTaskMode(t.Mode) {
		writeErr(w, 400, "仅 CTF / AD 任务支持 Phase-0 Precheck")
		return
	}
	res, err := s.ctfService().RunPrecheck(r.Context(), id, true)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	t.Notify()
	writeJSON(w, 200, res)
}

func (s *Server) taskBoardGet(w http.ResponseWriter, r *http.Request) {
	_, id, done, ok := s.taskOp(w, r)
	if !ok {
		return
	}
	defer done()
	items, err := s.m.pg.ListBoardItems(r.Context(), id, r.URL.Query().Get("kind"))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	kits, err := s.m.pg.ListBoardKits(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if items == nil {
		items = []db.BoardItem{}
	}
	if kits == nil {
		kits = []db.BoardKit{}
	}
	writeJSON(w, 200, map[string]any{"items": items, "kits": kits})
}

func (s *Server) taskBoardItemGet(w http.ResponseWriter, r *http.Request) {
	_, id, done, ok := s.taskOp(w, r)
	if !ok {
		return
	}
	defer done()
	itemID, err := strconv.ParseInt(r.PathValue("itemID"), 10, 64)
	if err != nil || itemID <= 0 {
		writeErr(w, 400, "无效看板节点 ID")
		return
	}
	item, err := s.m.pg.GetBoardItem(r.Context(), id, itemID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if item == nil {
		writeErr(w, 404, "看板节点不存在")
		return
	}
	writeJSON(w, 200, item)
}

func (s *Server) taskBoardSavepointCreate(w http.ResponseWriter, r *http.Request) {
	t, id, done, ok := s.taskOp(w, r)
	if !ok {
		return
	}
	defer done()
	var in struct {
		Title      string `json:"title"`
		Summary    string `json:"summary"`
		Detail     string `json:"detail"`
		CheckCmd   string `json:"check_cmd"`
		SnapshotID string `json:"snapshot_id"`
		IntentID   int64  `json:"intent_id"`
		ParentID   *int64 `json:"parent_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&in); err != nil {
		writeErr(w, 400, "请求无效")
		return
	}
	svc := s.ctfService()
	verified := false
	meta := map[string]any{}
	if strings.TrimSpace(in.CheckCmd) != "" {
		chk, err := svc.VerifyCheck(r.Context(), id, in.IntentID, in.CheckCmd, 60)
		if err != nil {
			writeErr(w, 409, err.Error())
			return
		}
		meta["execution_id"] = chk.ExecutionID
		meta["check_exit_code"] = chk.ExitCode
		if !chk.Passed {
			writeErr(w, 409, "Check 验真未通过: "+chk.StderrExcerpt)
			return
		}
		verified = true
	}
	snapID := strings.TrimSpace(in.SnapshotID)
	if snapID == "" {
		snapID = "sp-" + strconv.FormatInt(time.Now().UnixMilli(), 10)
	}
	spRes, err := svc.CreateSavepoint(r.Context(), id, in.IntentID, snapID)
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	meta["snapshot_path"] = spRes.Path
	metaRaw, _ := json.Marshal(meta)
	item, err := s.m.pg.AddBoardItem(r.Context(), db.BoardItem{
		TaskID:     id,
		ParentID:   in.ParentID,
		Kind:       db.BoardKindSavepoint,
		Title:      in.Title,
		Summary:    in.Summary,
		Detail:     in.Detail,
		SnapshotID: spRes.ID,
		CheckCmd:   in.CheckCmd,
		Verified:   verified,
		Meta:       metaRaw,
	})
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	t.Notify()
	writeJSON(w, 201, item)
}

func (s *Server) taskBoardRewind(w http.ResponseWriter, r *http.Request) {
	t, id, done, ok := s.taskOp(w, r)
	if !ok {
		return
	}
	defer done()
	var in struct {
		SavepointID   int64  `json:"savepoint_id"`
		DeadendTitle  string `json:"deadend_title"`
		DeadendReason string `json:"deadend_reason"`
		Detail        string `json:"detail"`
		IntentID      int64  `json:"intent_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&in); err != nil {
		writeErr(w, 400, "请求无效")
		return
	}
	sp, err := s.m.pg.GetBoardItem(r.Context(), id, in.SavepointID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if sp == nil || sp.Kind != db.BoardKindSavepoint || sp.SnapshotID == "" {
		writeErr(w, 404, "存档点不存在或无快照 ID")
		return
	}
	rwRes, err := s.ctfService().Rewind(r.Context(), id, in.IntentID, sp.SnapshotID)
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	title := strings.TrimSpace(in.DeadendTitle)
	if title == "" {
		title = "手动读档回滚"
	}
	reason := strings.TrimSpace(in.DeadendReason)
	if reason == "" {
		reason = "由控制台或指令触发回滚至 Savepoint #" + strconv.FormatInt(sp.ID, 10)
	}
	deadend, count, err := s.m.pg.RecordRewindAndDeadend(r.Context(), id, sp.ID, title, reason, in.Detail)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	t.Notify()
	writeJSON(w, 200, map[string]any{
		"rewound":        rwRes.Rewound,
		"snapshot_id":    sp.SnapshotID,
		"savepoint_id":   sp.ID,
		"rewind_count":   count,
		"deadend_record": deadend,
	})
}

func (s *Server) listGlobalKits(w http.ResponseWriter, r *http.Request) {
	taskIDStr := strings.TrimSpace(r.URL.Query().Get("task_id"))
	if taskIDStr != "" {
		taskID, err := strconv.ParseInt(taskIDStr, 10, 64)
		if err != nil || taskID <= 0 {
			writeErr(w, 400, "无效 task_id")
			return
		}
		kits, err := s.m.pg.ListBoardKits(r.Context(), taskID)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		if kits == nil {
			kits = []db.BoardKit{}
		}
		writeJSON(w, 200, kits)
		return
	}
	limit := 50
	if rawLim, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && rawLim > 0 {
		limit = rawLim
	}
	kits, err := s.m.pg.ListAllBoardKits(r.Context(), limit)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if kits == nil {
		kits = []db.BoardKit{}
	}
	writeJSON(w, 200, kits)
}

func (s *Server) listTips(w http.ResponseWriter, r *http.Request) {
	cat := r.URL.Query().Get("category")
	rawTags := strings.TrimSpace(r.URL.Query().Get("tags"))
	limit := 50
	if rawLim, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && rawLim > 0 {
		limit = rawLim
	}
	var (
		tips []db.TipCard
		err  error
	)
	if rawTags != "" {
		tags := strings.Split(rawTags, ",")
		tips, err = s.m.pg.SearchTips(r.Context(), cat, tags, limit)
	} else {
		tips, err = s.m.pg.ListTips(r.Context(), cat, limit)
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if tips == nil {
		tips = []db.TipCard{}
	}
	writeJSON(w, 200, tips)
}

func (s *Server) createTip(w http.ResponseWriter, r *http.Request) {
	var in db.TipCard
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32768)).Decode(&in); err != nil {
		writeErr(w, 400, "请求无效")
		return
	}
	card, err := s.m.pg.CreateTipCard(r.Context(), in)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 201, card)
}

func (s *Server) deleteTip(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("tipID"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "无效 Tip ID")
		return
	}
	if err := s.m.pg.DeleteTipCard(r.Context(), id); err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
