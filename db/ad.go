package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	ADWeaponActive  = "active"
	ADWeaponBlocked = "blocked"
	ADWeaponPaused  = "paused"
)

// ADWeapon represents a reusable exploit script periodically executed by the 0-LLM Repeater.
type ADWeapon struct {
	ID               int64      `json:"id"`
	TaskID           int64      `json:"task_id"`
	TargetService    string     `json:"target_service"`
	ScriptPath       string     `json:"script_path"`
	CheckCmd         string     `json:"check_cmd"`
	Status           string     `json:"status"`
	Targets          []string   `json:"targets"`
	FlagRegex        string     `json:"flag_regex,omitempty"`
	SubmitURL        string     `json:"submit_url,omitempty"`
	SubmitToken      string     `json:"submit_token,omitempty"`
	IntervalSec      int        `json:"interval_sec"`
	SuccessCount     int64      `json:"success_count"`
	FailCount        int64      `json:"fail_count"`
	ConsecutiveFails int        `json:"consecutive_fails"`
	LastFlag         string     `json:"last_flag,omitempty"`
	LastError        string     `json:"last_error,omitempty"`
	LastRunAt        *time.Time `json:"last_run_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
}

// ADEvent stores telemetry/alerts/decisions produced by Lead, Repeater, Catcher, and Patcher.
type ADEvent struct {
	ID        int64           `json:"id"`
	TaskID    int64           `json:"task_id"`
	WeaponID  *int64          `json:"weapon_id,omitempty"`
	Role      string          `json:"role"`
	Kind      string          `json:"kind"`
	Target    string          `json:"target,omitempty"`
	Summary   string          `json:"summary"`
	Detail    json.RawMessage `json:"detail_json,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}

func validADWeaponStatus(s string) bool {
	switch s {
	case ADWeaponActive, ADWeaponBlocked, ADWeaponPaused:
		return true
	default:
		return false
	}
}

// CreateADWeapon registers an exploit weapon script for Attack-Defense tasks.
func (d *DB) CreateADWeapon(ctx context.Context, w ADWeapon) (*ADWeapon, error) {
	if d == nil || w.TaskID <= 0 {
		return nil, fmt.Errorf("task_id is required")
	}
	w.TargetService = strings.TrimSpace(w.TargetService)
	w.ScriptPath = strings.TrimSpace(w.ScriptPath)
	w.CheckCmd = strings.TrimSpace(w.CheckCmd)
	if w.CheckCmd == "" && w.ScriptPath == "" {
		return nil, fmt.Errorf("check_cmd or script_path is required")
	}
	if w.CheckCmd == "" {
		w.CheckCmd = "python3 " + w.ScriptPath + " {TARGET}"
	}
	w.Status = strings.ToLower(strings.TrimSpace(w.Status))
	if w.Status == "" {
		w.Status = ADWeaponActive
	}
	if !validADWeaponStatus(w.Status) {
		return nil, fmt.Errorf("invalid weapon status %q", w.Status)
	}
	if w.IntervalSec <= 0 {
		w.IntervalSec = 60
	}
	if w.IntervalSec < 10 {
		w.IntervalSec = 10
	}
	targets := w.Targets
	if targets == nil {
		targets = []string{}
	}
	targetsJSON, _ := json.Marshal(targets)

	var out ADWeapon
	var targetsRaw string
	var lastRun sql.NullTime
	err := d.QueryRowContext(ctx, `
		INSERT INTO ad_weapons (
			task_id, target_service, script_path, check_cmd, status,
			targets_json, flag_regex, submit_url, submit_token, interval_sec
		) VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9,$10)
		RETURNING id, task_id, target_service, script_path, check_cmd, status,
			targets_json::text, flag_regex, submit_url, submit_token, interval_sec,
			success_count, fail_count, consecutive_fails, last_flag, last_error, last_run_at, created_at
	`, w.TaskID, w.TargetService, w.ScriptPath, w.CheckCmd, w.Status,
		string(targetsJSON), strings.TrimSpace(w.FlagRegex), strings.TrimSpace(w.SubmitURL), strings.TrimSpace(w.SubmitToken), w.IntervalSec,
	).Scan(
		&out.ID, &out.TaskID, &out.TargetService, &out.ScriptPath, &out.CheckCmd, &out.Status,
		&targetsRaw, &out.FlagRegex, &out.SubmitURL, &out.SubmitToken, &out.IntervalSec,
		&out.SuccessCount, &out.FailCount, &out.ConsecutiveFails, &out.LastFlag, &out.LastError, &lastRun, &out.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(targetsRaw), &out.Targets)
	if out.Targets == nil {
		out.Targets = []string{}
	}
	if lastRun.Valid {
		t := lastRun.Time
		out.LastRunAt = &t
	}
	return &out, nil
}

// GetADWeapon loads a single ADWeapon by taskID + weaponID.
func (d *DB) GetADWeapon(ctx context.Context, taskID, id int64) (*ADWeapon, error) {
	if d == nil || taskID <= 0 || id <= 0 {
		return nil, nil
	}
	var out ADWeapon
	var targetsRaw string
	var lastRun sql.NullTime
	err := d.QueryRowContext(ctx, `
		SELECT id, task_id, target_service, script_path, check_cmd, status,
			targets_json::text, flag_regex, submit_url, submit_token, interval_sec,
			success_count, fail_count, consecutive_fails, last_flag, last_error, last_run_at, created_at
		FROM ad_weapons WHERE task_id=$1 AND id=$2
	`, taskID, id).Scan(
		&out.ID, &out.TaskID, &out.TargetService, &out.ScriptPath, &out.CheckCmd, &out.Status,
		&targetsRaw, &out.FlagRegex, &out.SubmitURL, &out.SubmitToken, &out.IntervalSec,
		&out.SuccessCount, &out.FailCount, &out.ConsecutiveFails, &out.LastFlag, &out.LastError, &lastRun, &out.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	_ = json.Unmarshal([]byte(targetsRaw), &out.Targets)
	if out.Targets == nil {
		out.Targets = []string{}
	}
	if lastRun.Valid {
		t := lastRun.Time
		out.LastRunAt = &t
	}
	return &out, nil
}

// ListADWeapons lists registered AD weapons for taskID (or all active weapons across open tasks if taskID == 0).
func (d *DB) ListADWeapons(ctx context.Context, taskID int64) ([]ADWeapon, error) {
	if d == nil {
		return nil, nil
	}
	q := `
		SELECT id, task_id, target_service, script_path, check_cmd, status,
			targets_json::text, flag_regex, submit_url, submit_token, interval_sec,
			success_count, fail_count, consecutive_fails, last_flag, last_error, last_run_at, created_at
		FROM ad_weapons
	`
	var args []any
	if taskID > 0 {
		q += ` WHERE task_id=$1`
		args = append(args, taskID)
	} else {
		q += ` WHERE status='active'`
	}
	q += ` ORDER BY id ASC`
	rows, err := d.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ADWeapon
	for rows.Next() {
		var w ADWeapon
		var targetsRaw string
		var lastRun sql.NullTime
		if err := rows.Scan(
			&w.ID, &w.TaskID, &w.TargetService, &w.ScriptPath, &w.CheckCmd, &w.Status,
			&targetsRaw, &w.FlagRegex, &w.SubmitURL, &w.SubmitToken, &w.IntervalSec,
			&w.SuccessCount, &w.FailCount, &w.ConsecutiveFails, &w.LastFlag, &w.LastError, &lastRun, &w.CreatedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(targetsRaw), &w.Targets)
		if w.Targets == nil {
			w.Targets = []string{}
		}
		if lastRun.Valid {
			t := lastRun.Time
			w.LastRunAt = &t
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// UpdateADWeapon updates status and/or targets/interval for an AD weapon.
func (d *DB) UpdateADWeapon(ctx context.Context, taskID, id int64, status string, targets []string, intervalSec int) (*ADWeapon, error) {
	cur, err := d.GetADWeapon(ctx, taskID, id)
	if err != nil || cur == nil {
		return cur, err
	}
	if s := strings.ToLower(strings.TrimSpace(status)); s != "" {
		if !validADWeaponStatus(s) {
			return nil, fmt.Errorf("invalid weapon status %q", status)
		}
		cur.Status = s
		if s == ADWeaponActive {
			cur.ConsecutiveFails = 0
		}
	}
	if targets != nil {
		cur.Targets = targets
	}
	if intervalSec > 0 {
		cur.IntervalSec = max(intervalSec, 10)
	}
	targetsJSON, _ := json.Marshal(cur.Targets)
	_, err = d.ExecContext(ctx, `
		UPDATE ad_weapons SET status=$3, targets_json=$4::jsonb, interval_sec=$5, consecutive_fails=$6
		WHERE task_id=$1 AND id=$2
	`, taskID, id, cur.Status, string(targetsJSON), cur.IntervalSec, cur.ConsecutiveFails)
	if err != nil {
		return nil, err
	}
	return d.GetADWeapon(ctx, taskID, id)
}

// RecordADWeaponRun updates execution metrics and automatically flips status to 'blocked'
// after >=3 consecutive failures so Stop-Loss triggers promptly.
func (d *DB) RecordADWeaponRun(ctx context.Context, taskID, weaponID int64, successes, fails int, lastFlag, lastErr string) (*ADWeapon, error) {
	if d == nil || taskID <= 0 || weaponID <= 0 {
		return nil, fmt.Errorf("invalid ids")
	}
	cur, err := d.GetADWeapon(ctx, taskID, weaponID)
	if err != nil || cur == nil {
		return cur, err
	}
	consec := cur.ConsecutiveFails
	nextStatus := cur.Status
	if successes > 0 {
		consec = 0
	} else if fails > 0 {
		consec++
		if consec >= 3 && nextStatus == ADWeaponActive {
			nextStatus = ADWeaponBlocked
		}
	}
	if strings.TrimSpace(lastFlag) == "" {
		lastFlag = cur.LastFlag
	}
	_, err = d.ExecContext(ctx, `
		UPDATE ad_weapons
		SET success_count = success_count + $3,
			fail_count = fail_count + $4,
			consecutive_fails = $5,
			status = $6,
			last_flag = $7,
			last_error = $8,
			last_run_at = NOW()
		WHERE task_id=$1 AND id=$2
	`, taskID, weaponID, successes, fails, consec, nextStatus, strings.TrimSpace(lastFlag), strings.TrimSpace(lastErr))
	if err != nil {
		return nil, err
	}
	return d.GetADWeapon(ctx, taskID, weaponID)
}

// DeleteADWeapon deletes a weapon row scoped to taskID.
func (d *DB) DeleteADWeapon(ctx context.Context, taskID, id int64) error {
	if d == nil || taskID <= 0 || id <= 0 {
		return nil
	}
	_, err := d.ExecContext(ctx, `DELETE FROM ad_weapons WHERE task_id=$1 AND id=$2`, taskID, id)
	return err
}

// AddADEvent records an Attack-Defense telemetry or decision event.
func (d *DB) AddADEvent(ctx context.Context, ev ADEvent) (*ADEvent, error) {
	if d == nil || ev.TaskID <= 0 {
		return nil, fmt.Errorf("task_id required")
	}
	ev.Role = strings.ToLower(strings.TrimSpace(ev.Role))
	ev.Kind = strings.ToLower(strings.TrimSpace(ev.Kind))
	ev.Summary = strings.TrimSpace(ev.Summary)
	if ev.Role == "" || ev.Kind == "" || ev.Summary == "" {
		return nil, fmt.Errorf("role, kind and summary required")
	}
	detail := normalizeJSONObject(ev.Detail)
	var wid sql.NullInt64
	if ev.WeaponID != nil && *ev.WeaponID > 0 {
		wid = sql.NullInt64{Int64: *ev.WeaponID, Valid: true}
	}
	var out ADEvent
	var outWID sql.NullInt64
	var detailStr string
	err := d.QueryRowContext(ctx, `
		INSERT INTO ad_events (task_id, weapon_id, role, kind, target, summary, detail_json)
		VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
		RETURNING id, task_id, weapon_id, role, kind, target, summary, detail_json::text, created_at
	`, ev.TaskID, wid, ev.Role, ev.Kind, strings.TrimSpace(ev.Target), ev.Summary, string(detail)).Scan(
		&out.ID, &out.TaskID, &outWID, &out.Role, &out.Kind, &out.Target, &out.Summary, &detailStr, &out.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	if outWID.Valid {
		v := outWID.Int64
		out.WeaponID = &v
	}
	out.Detail = json.RawMessage(detailStr)
	return &out, nil
}

// ListADEvents returns most recent AD events for taskID (newest first).
func (d *DB) ListADEvents(ctx context.Context, taskID int64, limit int) ([]ADEvent, error) {
	if d == nil || taskID <= 0 {
		return nil, nil
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := d.QueryContext(ctx, `
		SELECT id, task_id, weapon_id, role, kind, target, summary, detail_json::text, created_at
		FROM ad_events WHERE task_id=$1 ORDER BY id DESC LIMIT $2
	`, taskID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ADEvent
	for rows.Next() {
		var ev ADEvent
		var wid sql.NullInt64
		var detailStr string
		if err := rows.Scan(&ev.ID, &ev.TaskID, &wid, &ev.Role, &ev.Kind, &ev.Target, &ev.Summary, &detailStr, &ev.CreatedAt); err != nil {
			return nil, err
		}
		if wid.Valid {
			v := wid.Int64
			ev.WeaponID = &v
		}
		ev.Detail = json.RawMessage(detailStr)
		out = append(out, ev)
	}
	return out, rows.Err()
}
