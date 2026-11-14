package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"p3y/ad"
	"p3y/db"
	"github.com/Autumn-27/norma/llm"
)

func (s *Server) adService() *ad.Service {
	var pg *db.DB
	var tr = s.m.traffic
	if s.m != nil {
		pg = s.m.pg
	}
	return &ad.Service{
		DB:      pg,
		CTF:     s.ctfService(),
		Traffic: tr,
	}
}

func (s *Server) startADRepeaterLoop() {
	if s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(s.ctx, 25*time.Second)
				_ = s.adService().TickDueWeapons(ctx)
				cancel()
			}
		}
	}()
}

func (s *Server) taskADOverview(w http.ResponseWriter, r *http.Request) {
	_, id, done, ok := s.taskOp(w, r)
	if !ok {
		return
	}
	defer done()
	ov, err := s.adService().Overview(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, ov)
}

func (s *Server) taskADWeaponCreate(w http.ResponseWriter, r *http.Request) {
	_, id, done, ok := s.taskOp(w, r)
	if !ok {
		return
	}
	defer done()
	var in db.ADWeapon
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32768)).Decode(&in); err != nil {
		writeErr(w, 400, "请求无效")
		return
	}
	in.TaskID = id
	created, err := s.m.pg.CreateADWeapon(r.Context(), in)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 201, created)
}

func (s *Server) taskADWeaponUpdate(w http.ResponseWriter, r *http.Request) {
	_, id, done, ok := s.taskOp(w, r)
	if !ok {
		return
	}
	defer done()
	wid, err := strconv.ParseInt(r.PathValue("weaponID"), 10, 64)
	if err != nil || wid <= 0 {
		writeErr(w, 400, "无效武器 ID")
		return
	}
	var in struct {
		Status      string   `json:"status"`
		Targets     []string `json:"targets"`
		IntervalSec int      `json:"interval_sec"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32768)).Decode(&in); err != nil {
		writeErr(w, 400, "请求无效")
		return
	}
	updated, err := s.m.pg.UpdateADWeapon(r.Context(), id, wid, in.Status, in.Targets, in.IntervalSec)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if updated == nil {
		writeErr(w, 404, "武器不存在")
		return
	}
	writeJSON(w, 200, updated)
}

func (s *Server) taskADWeaponDelete(w http.ResponseWriter, r *http.Request) {
	_, id, done, ok := s.taskOp(w, r)
	if !ok {
		return
	}
	defer done()
	wid, err := strconv.ParseInt(r.PathValue("weaponID"), 10, 64)
	if err != nil || wid <= 0 {
		writeErr(w, 400, "无效武器 ID")
		return
	}
	if err := s.m.pg.DeleteADWeapon(r.Context(), id, wid); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) taskADRepeaterRun(w http.ResponseWriter, r *http.Request) {
	_, id, done, ok := s.taskOp(w, r)
	if !ok {
		return
	}
	defer done()
	var in struct {
		WeaponID int64 `json:"weapon_id"`
		Force    bool  `json:"force"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in)
	}
	if !in.Force {
		in.Force = true
	}
	res, err := s.adService().RunRepeater(r.Context(), id, in.WeaponID, in.Force)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, res)
}

func (s *Server) taskADCatcherScan(w http.ResponseWriter, r *http.Request) {
	_, id, done, ok := s.taskOp(w, r)
	if !ok {
		return
	}
	defer done()
	var in struct {
		Samples     []ad.CatcherSample `json:"samples"`
		RecordBoard *bool              `json:"record_board"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in)
	}
	rec := true
	if in.RecordBoard != nil {
		rec = *in.RecordBoard
	}
	res, err := s.adService().ScanCatcher(r.Context(), id, in.Samples, rec)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, res)
}

func (s *Server) taskADPatcherVerify(w http.ResponseWriter, r *http.Request) {
	_, id, done, ok := s.taskOp(w, r)
	if !ok {
		return
	}
	defer done()
	var spec ad.PatchVerifySpec
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32768)).Decode(&spec); err != nil {
		writeErr(w, 400, "请求无效")
		return
	}
	res, err := s.adService().VerifyPatch(r.Context(), id, spec)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, res)
}

func (s *Server) taskTipsCrystallize(w http.ResponseWriter, r *http.Request) {
	t, id, done, ok := s.taskOp(w, r)
	if !ok {
		return
	}
	defer done()
	var prov llm.Provider
	if s.engine != nil && s.engine.ReadyFor(t) {
		prov = &taskLLMRuntime{s: s, taskID: t.ID, agentKey: "mainagent"}
	}
	cards, err := s.ctfService().CrystallizeTips(r.Context(), id, prov)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if cards == nil {
		cards = []db.TipCard{}
	}
	writeJSON(w, 200, map[string]any{"cards": cards})
}
