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
	BoardKindFact      = "fact"
	BoardKindStep      = "step"
	BoardKindSavepoint = "savepoint"
	BoardKindDeadend   = "deadend"
)

// BoardItem represents a single node on the shared p3y state board with 3-tier
// progressive disclosure: Title (L1) / Summary (L2) / Detail (L3).
type BoardItem struct {
	ID         int64           `json:"id"`
	TaskID     int64           `json:"task_id"`
	ParentID   *int64          `json:"parent_id,omitempty"`
	Kind       string          `json:"kind"`
	Title      string          `json:"title"`
	Summary    string          `json:"summary"`
	Detail     string          `json:"detail,omitempty"`
	SnapshotID string          `json:"snapshot_id,omitempty"`
	CheckCmd   string          `json:"check_cmd,omitempty"`
	Verified   bool            `json:"verified"`
	Meta       json.RawMessage `json:"meta_json,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
}

// BoardKit represents a verified reusable workspace artifact (e.g. interact.py,
// symbols.json, stage1_leak.py, exp.py) anchored to a task / savepoint.
// When its originating task is deleted, TaskID becomes 0 while Content and
// SourceTaskName remain preserved in the global kit library.
type BoardKit struct {
	ID             int64           `json:"id"`
	TaskID         int64           `json:"task_id"`
	SourceTaskName string          `json:"source_task_name,omitempty"`
	SavepointID    *int64          `json:"savepoint_id,omitempty"`
	Name           string          `json:"name"`
	Path           string          `json:"path"`
	Summary        string          `json:"summary"`
	Content        string          `json:"content,omitempty"`
	SHA256         string          `json:"sha256,omitempty"`
	Verified       bool            `json:"verified"`
	Meta           json.RawMessage `json:"meta_json,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
}

func validBoardKind(kind string) bool {
	switch kind {
	case BoardKindFact, BoardKindStep, BoardKindSavepoint, BoardKindDeadend:
		return true
	default:
		return false
	}
}

func normalizeJSONObject(raw json.RawMessage) json.RawMessage {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || !json.Valid([]byte(trimmed)) {
		return json.RawMessage(`{}`)
	}
	return json.RawMessage(trimmed)
}

// SaveTaskPrecheck persists the deterministic Phase-0 Precheck JSON onto the task row.
func (d *DB) SaveTaskPrecheck(ctx context.Context, taskID int64, raw json.RawMessage) error {
	if d == nil || taskID <= 0 {
		return fmt.Errorf("invalid task id")
	}
	if !json.Valid(raw) {
		return fmt.Errorf("invalid precheck json")
	}
	_, err := d.ExecContext(ctx,
		`UPDATE tasks SET precheck_result=$2 WHERE id=$1 AND deleted_at IS NULL`,
		taskID, string(raw),
	)
	return err
}

// TaskPrecheck returns the persisted Phase-0 Precheck JSON for taskID, or nil if absent.
func (d *DB) TaskPrecheck(ctx context.Context, taskID int64) (json.RawMessage, error) {
	if d == nil || taskID <= 0 {
		return nil, nil
	}
	var raw sql.NullString
	err := d.QueryRowContext(ctx,
		`SELECT precheck_result::text FROM tasks WHERE id=$1 AND deleted_at IS NULL`,
		taskID,
	).Scan(&raw)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if !raw.Valid || strings.TrimSpace(raw.String) == "" {
		return nil, nil
	}
	return json.RawMessage(raw.String), nil
}

// AddBoardItem inserts a board item (fact / step / savepoint / deadend) into board_items.
func (d *DB) AddBoardItem(ctx context.Context, item BoardItem) (*BoardItem, error) {
	if d == nil || item.TaskID <= 0 {
		return nil, fmt.Errorf("task_id is required")
	}
	item.Kind = strings.ToLower(strings.TrimSpace(item.Kind))
	if !validBoardKind(item.Kind) {
		return nil, fmt.Errorf("invalid board item kind %q", item.Kind)
	}
	item.Title = strings.TrimSpace(item.Title)
	item.Summary = strings.TrimSpace(item.Summary)
	if item.Title == "" {
		item.Title = item.Summary
	}
	if item.Title == "" {
		return nil, fmt.Errorf("board item title/summary required")
	}
	meta := normalizeJSONObject(item.Meta)
	var parent sql.NullInt64
	if item.ParentID != nil && *item.ParentID > 0 {
		parent = sql.NullInt64{Int64: *item.ParentID, Valid: true}
	}
	var out BoardItem
	var outParent sql.NullInt64
	var outMeta string
	err := d.QueryRowContext(ctx, `
		INSERT INTO board_items (task_id, parent_id, kind, title, summary, detail, snapshot_id, check_cmd, verified, meta_json)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb)
		RETURNING id, task_id, parent_id, kind, title, summary, detail, snapshot_id, check_cmd, verified, meta_json::text, created_at
	`, item.TaskID, parent, item.Kind, item.Title, item.Summary, item.Detail,
		strings.TrimSpace(item.SnapshotID), strings.TrimSpace(item.CheckCmd), item.Verified, string(meta),
	).Scan(&out.ID, &out.TaskID, &outParent, &out.Kind, &out.Title, &out.Summary, &out.Detail,
		&out.SnapshotID, &out.CheckCmd, &out.Verified, &outMeta, &out.CreatedAt)
	if err != nil {
		return nil, err
	}
	if outParent.Valid {
		v := outParent.Int64
		out.ParentID = &v
	}
	out.Meta = json.RawMessage(outMeta)
	return &out, nil
}

// GetBoardItem loads the full L1/L2/L3 board item by task_id and id.
func (d *DB) GetBoardItem(ctx context.Context, taskID, id int64) (*BoardItem, error) {
	if d == nil || taskID <= 0 || id <= 0 {
		return nil, nil
	}
	var out BoardItem
	var parent sql.NullInt64
	var meta string
	err := d.QueryRowContext(ctx, `
		SELECT id, task_id, parent_id, kind, title, summary, detail, snapshot_id, check_cmd, verified, meta_json::text, created_at
		FROM board_items WHERE task_id=$1 AND id=$2
	`, taskID, id).Scan(&out.ID, &out.TaskID, &parent, &out.Kind, &out.Title, &out.Summary, &out.Detail,
		&out.SnapshotID, &out.CheckCmd, &out.Verified, &meta, &out.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if parent.Valid {
		v := parent.Int64
		out.ParentID = &v
	}
	out.Meta = json.RawMessage(meta)
	return &out, nil
}

// ListBoardItems returns board items for taskID (optionally filtered by kind).
func (d *DB) ListBoardItems(ctx context.Context, taskID int64, kind string) ([]BoardItem, error) {
	if d == nil || taskID <= 0 {
		return nil, nil
	}
	kind = strings.ToLower(strings.TrimSpace(kind))
	query := `
		SELECT id, task_id, parent_id, kind, title, summary, detail, snapshot_id, check_cmd, verified, meta_json::text, created_at
		FROM board_items WHERE task_id=$1`
	args := []any{taskID}
	if kind != "" {
		query += ` AND kind=$2`
		args = append(args, kind)
	}
	query += ` ORDER BY id ASC`
	rows, err := d.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []BoardItem
	for rows.Next() {
		var it BoardItem
		var parent sql.NullInt64
		var meta string
		if err := rows.Scan(&it.ID, &it.TaskID, &parent, &it.Kind, &it.Title, &it.Summary, &it.Detail,
			&it.SnapshotID, &it.CheckCmd, &it.Verified, &meta, &it.CreatedAt); err != nil {
			return nil, err
		}
		if parent.Valid {
			v := parent.Int64
			it.ParentID = &v
		}
		it.Meta = json.RawMessage(meta)
		items = append(items, it)
	}
	return items, rows.Err()
}

// UpsertBoardItemByTitle updates the latest matching item of (taskID, kind, title) or inserts one.
// Useful for idempotent Phase-0 Precheck records.
func (d *DB) UpsertBoardItemByTitle(ctx context.Context, item BoardItem) (*BoardItem, error) {
	if d == nil || item.TaskID <= 0 {
		return nil, fmt.Errorf("task_id is required")
	}
	item.Kind = strings.ToLower(strings.TrimSpace(item.Kind))
	item.Title = strings.TrimSpace(item.Title)
	var existingID int64
	err := d.QueryRowContext(ctx,
		`SELECT id FROM board_items WHERE task_id=$1 AND kind=$2 AND title=$3 ORDER BY id DESC LIMIT 1`,
		item.TaskID, item.Kind, item.Title,
	).Scan(&existingID)
	if err == sql.ErrNoRows {
		return d.AddBoardItem(ctx, item)
	}
	if err != nil {
		return nil, err
	}
	meta := normalizeJSONObject(item.Meta)
	_, err = d.ExecContext(ctx, `
		UPDATE board_items
		SET summary=$3, detail=$4, snapshot_id=$5, check_cmd=$6, verified=$7, meta_json=$8::jsonb
		WHERE task_id=$1 AND id=$2
	`, item.TaskID, existingID, strings.TrimSpace(item.Summary), item.Detail,
		strings.TrimSpace(item.SnapshotID), strings.TrimSpace(item.CheckCmd), item.Verified, string(meta))
	if err != nil {
		return nil, err
	}
	return d.GetBoardItem(ctx, item.TaskID, existingID)
}

// UpdateBoardItemMeta merges keys into meta_json (and optionally verified/check_cmd).
func (d *DB) UpdateBoardItemVerification(ctx context.Context, taskID, id int64, verified bool, checkCmd string, metaPatch map[string]any) error {
	if d == nil || taskID <= 0 || id <= 0 {
		return fmt.Errorf("invalid board item reference")
	}
	patchBytes, _ := json.Marshal(metaPatch)
	if len(metaPatch) == 0 {
		patchBytes = []byte(`{}`)
	}
	_, err := d.ExecContext(ctx, `
		UPDATE board_items
		SET verified=$3,
		    check_cmd=CASE WHEN $4 <> '' THEN $4 ELSE check_cmd END,
		    meta_json=COALESCE(meta_json, '{}'::jsonb) || $5::jsonb
		WHERE task_id=$1 AND id=$2
	`, taskID, id, verified, strings.TrimSpace(checkCmd), string(patchBytes))
	return err
}

// PatchBoardItemMeta merges metaPatch into a board item's meta_json without altering verified/check_cmd.
func (d *DB) PatchBoardItemMeta(ctx context.Context, taskID, id int64, metaPatch map[string]any) error {
	if d == nil || taskID <= 0 || id <= 0 || len(metaPatch) == 0 {
		return nil
	}
	patchBytes, err := json.Marshal(metaPatch)
	if err != nil {
		return err
	}
	_, err = d.ExecContext(ctx, `
		UPDATE board_items
		SET meta_json=COALESCE(meta_json, '{}'::jsonb) || $3::jsonb
		WHERE task_id=$1 AND id=$2
	`, taskID, id, string(patchBytes))
	return err
}

// RecordRewindAndDeadend increments rewind_count in the savepoint's meta_json and attaches a deadend child.
func (d *DB) RecordRewindAndDeadend(ctx context.Context, taskID, savepointID int64, title, reason, detail string) (*BoardItem, int, error) {
	sp, err := d.GetBoardItem(ctx, taskID, savepointID)
	if err != nil {
		return nil, 0, err
	}
	if sp == nil || sp.Kind != BoardKindSavepoint {
		return nil, 0, fmt.Errorf("savepoint #%d not found", savepointID)
	}
	var metaMap map[string]any
	_ = json.Unmarshal(sp.Meta, &metaMap)
	if metaMap == nil {
		metaMap = map[string]any{}
	}
	count := 0
	if v, ok := metaMap["rewind_count"].(float64); ok {
		count = int(v)
	}
	count++
	if err := d.UpdateBoardItemVerification(ctx, taskID, savepointID, sp.Verified, "", map[string]any{"rewind_count": count}); err != nil {
		return nil, 0, err
	}
	pid := savepointID
	deadend, err := d.AddBoardItem(ctx, BoardItem{
		TaskID:   taskID,
		ParentID: &pid,
		Kind:     BoardKindDeadend,
		Title:    strings.TrimSpace(title),
		Summary:  strings.TrimSpace(reason),
		Detail:   detail,
		Verified: true,
	})
	return deadend, count, err
}

// UpsertBoardKit saves or updates a verified workspace kit anchored to taskID.
func (d *DB) UpsertBoardKit(ctx context.Context, kit BoardKit) (*BoardKit, error) {
	if d == nil || kit.TaskID <= 0 {
		return nil, fmt.Errorf("task_id is required")
	}
	kit.Name = strings.TrimSpace(kit.Name)
	kit.Path = strings.TrimSpace(kit.Path)
	kit.Summary = strings.TrimSpace(kit.Summary)
	kit.Content = utf8Clean(kit.Content)
	kit.SourceTaskName = utf8Clean(strings.TrimSpace(kit.SourceTaskName))
	if kit.Name == "" {
		return nil, fmt.Errorf("kit name is required")
	}
	if kit.Path == "" {
		kit.Path = "/work/" + kit.Name
	}
	meta := normalizeJSONObject(kit.Meta)
	var sp sql.NullInt64
	if kit.SavepointID != nil && *kit.SavepointID > 0 {
		sp = sql.NullInt64{Int64: *kit.SavepointID, Valid: true}
	}
	var out BoardKit
	var outSP sql.NullInt64
	var outMeta string
	err := d.QueryRowContext(ctx, `
		INSERT INTO board_kits (task_id, source_task_name, savepoint_id, name, path, summary, content, sha256, verified, meta_json)
		VALUES (
			$1,
			COALESCE(NULLIF($2, ''), (SELECT COALESCE(NULLIF(name, ''), LEFT(goal, 80)) FROM tasks WHERE id=$1), ''),
			$3, $4, $5, $6, $7, $8, $9, $10::jsonb
		)
		ON CONFLICT (task_id, name) DO UPDATE SET
			source_task_name = CASE WHEN EXCLUDED.source_task_name <> '' THEN EXCLUDED.source_task_name ELSE board_kits.source_task_name END,
			savepoint_id     = EXCLUDED.savepoint_id,
			path             = EXCLUDED.path,
			summary          = EXCLUDED.summary,
			content          = CASE WHEN EXCLUDED.content <> '' THEN EXCLUDED.content ELSE board_kits.content END,
			sha256           = CASE WHEN EXCLUDED.sha256 <> '' THEN EXCLUDED.sha256 ELSE board_kits.sha256 END,
			verified         = EXCLUDED.verified,
			meta_json        = EXCLUDED.meta_json
		RETURNING id, COALESCE(task_id, 0), source_task_name, savepoint_id, name, path, summary, content, sha256, verified, meta_json::text, created_at
	`, kit.TaskID, kit.SourceTaskName, sp, kit.Name, kit.Path, kit.Summary, kit.Content, strings.TrimSpace(kit.SHA256), kit.Verified, string(meta),
	).Scan(&out.ID, &out.TaskID, &out.SourceTaskName, &outSP, &out.Name, &out.Path, &out.Summary, &out.Content, &out.SHA256, &out.Verified, &outMeta, &out.CreatedAt)
	if err != nil {
		return nil, err
	}
	if outSP.Valid {
		v := outSP.Int64
		out.SavepointID = &v
	}
	out.Meta = json.RawMessage(outMeta)
	return &out, nil
}

// BackfillBoardKitSnapshot populates missing sha256, content, or source_task_name
// on an existing kit row (used prior to task deletion so legacy kits stay reusable).
func (d *DB) BackfillBoardKitSnapshot(ctx context.Context, kitID int64, sha256, content, sourceTaskName string) error {
	if d == nil || kitID <= 0 {
		return nil
	}
	_, err := d.ExecContext(ctx, `
		UPDATE board_kits
		SET sha256           = CASE WHEN sha256 = '' AND $2 <> '' THEN $2 ELSE sha256 END,
		    content          = CASE WHEN content = '' AND $3 <> '' THEN $3 ELSE content END,
		    source_task_name = CASE WHEN source_task_name = '' AND $4 <> '' THEN $4 ELSE source_task_name END
		WHERE id = $1
	`, kitID, strings.TrimSpace(sha256), utf8Clean(content), utf8Clean(strings.TrimSpace(sourceTaskName)))
	return err
}

func scanBoardKits(rows *sql.Rows) ([]BoardKit, error) {
	defer rows.Close()
	var kits []BoardKit
	for rows.Next() {
		var k BoardKit
		var sp sql.NullInt64
		var meta string
		if err := rows.Scan(&k.ID, &k.TaskID, &k.SourceTaskName, &sp, &k.Name, &k.Path, &k.Summary, &k.Content, &k.SHA256, &k.Verified, &meta, &k.CreatedAt); err != nil {
			return nil, err
		}
		if sp.Valid {
			v := sp.Int64
			k.SavepointID = &v
		}
		k.Meta = json.RawMessage(meta)
		kits = append(kits, k)
	}
	return kits, rows.Err()
}

// ListBoardKits lists all kits saved for taskID.
func (d *DB) ListBoardKits(ctx context.Context, taskID int64) ([]BoardKit, error) {
	if d == nil || taskID <= 0 {
		return nil, nil
	}
	rows, err := d.QueryContext(ctx, `
		SELECT id, COALESCE(task_id, 0), source_task_name, savepoint_id, name, path, summary, content, sha256, verified, meta_json::text, created_at
		FROM board_kits WHERE task_id=$1 ORDER BY id ASC
	`, taskID)
	if err != nil {
		return nil, err
	}
	return scanBoardKits(rows)
}

// ListAllBoardKits returns verified/recent kits across tasks (including kits whose
// originating task was deleted, for the global Kits & Tips browser).
func (d *DB) ListAllBoardKits(ctx context.Context, limit int) ([]BoardKit, error) {
	if d == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := d.QueryContext(ctx, `
		SELECT id, COALESCE(task_id, 0), source_task_name, savepoint_id, name, path, summary, content, sha256, verified, meta_json::text, created_at
		FROM board_kits ORDER BY id DESC LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	return scanBoardKits(rows)
}

// RenderBoardIndex builds a compact L1/L2 shared-board digest (omitting L3 Detail
// bodies so prompt context stays lean).
func (d *DB) RenderBoardIndex(ctx context.Context, taskID int64) string {
	items, err := d.ListBoardItems(ctx, taskID, "")
	kits, kerr := d.ListBoardKits(ctx, taskID)
	if (err != nil || len(items) == 0) && (kerr != nil || len(kits) == 0) {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n【共享状态看板 Board（Savepoint / Deadend / Kit 索引）】\n")
	for _, it := range items {
		badge := strings.ToUpper(it.Kind)
		if it.Verified {
			badge += ":VERIFIED"
		}
		snap := ""
		if it.SnapshotID != "" {
			snap = fmt.Sprintf(" snap=%s", it.SnapshotID)
		}
		parent := ""
		if it.ParentID != nil && *it.ParentID > 0 {
			parent = fmt.Sprintf(" <- #%d", *it.ParentID)
		}
		detailHint := ""
		if strings.TrimSpace(it.Detail) != "" {
			detailHint = fmt.Sprintf(" [detail#%d]", it.ID)
		}
		fmt.Fprintf(&b, "- #%d [%s]%s%s: %s — %s%s\n", it.ID, badge, parent, snap, it.Title, it.Summary, detailHint)
	}
	if len(kits) > 0 {
		b.WriteString("【已沉淀套件 Kits（可直接 import 或复用）】\n")
		for _, k := range kits {
			status := "unverified"
			if k.Verified {
				status = "verified"
			}
			fmt.Fprintf(&b, "- kit#%d `%s` (%s, %s): %s\n", k.ID, k.Name, k.Path, status, k.Summary)
		}
	}
	return b.String()
}
