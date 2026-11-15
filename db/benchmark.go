package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

type BenchmarkTokenUsage struct {
	InputTokens      int64 `json:"input_tokens"`
	OutputTokens     int64 `json:"output_tokens"`
	CacheReadTokens  int64 `json:"cache_read_tokens"`
	CacheWriteTokens int64 `json:"cache_write_tokens"`
	TotalTokens      int64 `json:"total_tokens"`
}

type BenchmarkSession struct {
	ID                  int64               `json:"id"`
	Name                string              `json:"name"`
	Provider            string              `json:"provider"` // tsecbench | ctf2 | generic_mcp
	BaseURL             string              `json:"base_url"`
	Token               string              `json:"-"`
	HasToken            bool                `json:"has_token"`
	Config              json.RawMessage     `json:"config"`
	MaxConcurrent       int                 `json:"max_concurrent"`
	HintPolicy          string              `json:"hint_policy"` // never | stagnant_only
	PerChallengeTimeout int                 `json:"per_challenge_timeout"`
	LLMProfileIDs       []int64             `json:"llm_profile_ids"`
	Status              string              `json:"status"`
	TotalScore          int                 `json:"total_score"`
	MaxPossibleScore    int                 `json:"max_possible_score"`
	CompletedCount      int                 `json:"completed_count"`
	TotalCount          int                 `json:"total_count"`
	ActiveSlots         int                 `json:"active_slots"`
	Tokens              BenchmarkTokenUsage `json:"tokens"`
	LastError           string              `json:"last_error,omitempty"`
	StartedAt           *time.Time          `json:"started_at,omitempty"`
	FinishedAt          *time.Time          `json:"finished_at,omitempty"`
	CreatedAt           time.Time           `json:"created_at"`
	UpdatedAt           time.Time           `json:"updated_at"`
}

type BenchmarkChallenge struct {
	ID               int64               `json:"id"`
	SessionID        int64               `json:"session_id"`
	UniqueCode       string              `json:"unique_code"`
	Title            string              `json:"title"`
	Description      string              `json:"description"`
	Category         string              `json:"category"`
	Difficulty       string              `json:"difficulty"`
	Level            int                 `json:"level"`
	SubmissionType   string              `json:"submission_type"` // flag | suite | choice
	TotalScore       int                 `json:"total_score"`
	CumulativeScore  int                 `json:"cumulative_score"`
	FlagCount        int                 `json:"flag_count"`
	CorrectFlagCount int                 `json:"correct_flag_count"`
	IsCompleted      bool                `json:"is_completed"`
	ContainerStatus  string              `json:"container_status"`
	ContainerAddr    []string            `json:"container_addr"`
	EnvExpiresAt     *time.Time          `json:"env_expires_at,omitempty"`
	HintUsed         bool                `json:"hint_used"`
	HintContent      string              `json:"hint_content,omitempty"`
	BoundTaskID      *int64              `json:"bound_task_id,omitempty"`
	BoundTaskStatus  string              `json:"bound_task_status,omitempty"`
	Tokens           BenchmarkTokenUsage `json:"tokens"`
	AttemptCount     int                 `json:"attempt_count"`
	Meta             json.RawMessage     `json:"meta"`
	LastError        string              `json:"last_error,omitempty"`
	CreatedAt        time.Time           `json:"created_at"`
	UpdatedAt        time.Time           `json:"updated_at"`
}

type BenchmarkSubmission struct {
	ID               int64     `json:"id"`
	SessionID        int64     `json:"session_id"`
	UniqueCode       string    `json:"unique_code"`
	SubFlagID        string    `json:"sub_flag_id,omitempty"`
	AnswerValue      string    `json:"answer_value"`
	AnswerSHA256     string    `json:"answer_sha256"`
	Correct          bool      `json:"correct"`
	Awarded          int       `json:"awarded"`
	MatchedFlagIndex *int      `json:"matched_flag_index,omitempty"`
	HTTPStatus       int       `json:"http_status"`
	ErrorCode        string    `json:"error_code,omitempty"`
	Message          string    `json:"message,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
}

type BenchmarkEvent struct {
	ID         int64           `json:"id"`
	SessionID  int64           `json:"session_id"`
	UniqueCode string          `json:"unique_code,omitempty"`
	Kind       string          `json:"kind"`
	Summary    string          `json:"summary"`
	Detail     json.RawMessage `json:"detail"`
	CreatedAt  time.Time       `json:"created_at"`
}

type BenchmarkSessionCreate struct {
	Name                string
	Provider            string
	BaseURL             string
	Token               string
	Config              json.RawMessage
	MaxConcurrent       int
	HintPolicy          string
	PerChallengeTimeout int
	LLMProfileIDs       []int64
}

func NormalizeBenchmarkProvider(p string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "tsecbench":
		return "tsecbench", nil
	case "ctf2":
		return "ctf2", nil
	case "generic_mcp":
		return "generic_mcp", nil
	default:
		return "", errors.New("不支持的测评平台类型（可选 tsecbench / ctf2 / generic_mcp）")
	}
}

func NormalizeHintPolicy(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "stagnant_only":
		return "stagnant_only"
	default:
		return "never"
	}
}

const benchSessionCols = `id,name,provider,base_url,token,config_json,max_concurrent,hint_policy,per_challenge_timeout,llm_profile_ids,status,total_score,max_possible_score,completed_count,total_count,active_slots,last_error,started_at,finished_at,created_at,updated_at`

func scanBenchmarkSession(sc interface{ Scan(...any) error }) (*BenchmarkSession, error) {
	var s BenchmarkSession
	var cfg []byte
	var llmRaw string
	if err := sc.Scan(
		&s.ID, &s.Name, &s.Provider, &s.BaseURL, &s.Token, &cfg,
		&s.MaxConcurrent, &s.HintPolicy, &s.PerChallengeTimeout, &llmRaw,
		&s.Status, &s.TotalScore, &s.MaxPossibleScore, &s.CompletedCount, &s.TotalCount,
		&s.ActiveSlots, &s.LastError, &s.StartedAt, &s.FinishedAt, &s.CreatedAt, &s.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if len(cfg) == 0 {
		s.Config = json.RawMessage(`{}`)
	} else {
		s.Config = json.RawMessage(cfg)
	}
	s.HasToken = strings.TrimSpace(s.Token) != ""
	s.LLMProfileIDs = parsePGInt64Array(llmRaw)
	return &s, nil
}

func parsePGInt64Array(raw string) []int64 {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "{")
	raw = strings.TrimSuffix(raw, "}")
	raw = strings.TrimPrefix(raw, "[")
	raw = strings.TrimSuffix(raw, "]")
	if strings.TrimSpace(raw) == "" {
		return []int64{}
	}
	parts := strings.Split(raw, ",")
	out := make([]int64, 0, len(parts))
	for _, p := range parts {
		if n, err := strconv.ParseInt(strings.TrimSpace(p), 10, 64); err == nil && n > 0 {
			out = append(out, n)
		}
	}
	return out
}

func formatPGInt64Array(ids []int64) string {
	if len(ids) == 0 {
		return "{}"
	}
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		if id > 0 {
			parts = append(parts, strconv.FormatInt(id, 10))
		}
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func (d *DB) CreateBenchmarkSession(ctx context.Context, in BenchmarkSessionCreate) (*BenchmarkSession, error) {
	prov, err := NormalizeBenchmarkProvider(in.Provider)
	if err != nil {
		return nil, err
	}
	maxConc := in.MaxConcurrent
	if maxConc <= 0 {
		if prov == "ctf2" {
			maxConc = 1
		} else {
			maxConc = 3
		}
	}
	if maxConc > 16 {
		maxConc = 16
	}
	timeoutSec := in.PerChallengeTimeout
	if timeoutSec <= 0 {
		timeoutSec = 1500
	}
	cfg := in.Config
	if len(cfg) == 0 {
		cfg = json.RawMessage(`{}`)
	}
	hintPolicy := NormalizeHintPolicy(in.HintPolicy)
	profiles := in.LLMProfileIDs
	if profiles == nil {
		profiles = []int64{}
	}
	row := d.QueryRowContext(ctx, `
INSERT INTO benchmark_sessions(name,provider,base_url,token,config_json,max_concurrent,hint_policy,per_challenge_timeout,llm_profile_ids)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::bigint[])
RETURNING `+benchSessionCols,
		strings.TrimSpace(in.Name), prov, strings.TrimSpace(in.BaseURL), strings.TrimSpace(in.Token),
		[]byte(cfg), maxConc, hintPolicy, timeoutSec, formatPGInt64Array(profiles),
	)
	return scanBenchmarkSession(row)
}

func (d *DB) ListBenchmarkSessions(ctx context.Context) ([]*BenchmarkSession, error) {
	rows, err := d.QueryContext(ctx, `SELECT `+benchSessionCols+` FROM benchmark_sessions ORDER BY id DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*BenchmarkSession{}
	for rows.Next() {
		s, err := scanBenchmarkSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (d *DB) GetBenchmarkSession(ctx context.Context, id int64) (*BenchmarkSession, error) {
	s, err := scanBenchmarkSession(d.QueryRowContext(ctx, `SELECT `+benchSessionCols+` FROM benchmark_sessions WHERE id=$1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return s, err
}

func (d *DB) UpdateBenchmarkSessionStatus(ctx context.Context, id int64, status, lastError string) error {
	var startedExpr = `started_at`
	var finishedExpr = `finished_at`
	switch status {
	case "running":
		startedExpr = `COALESCE(started_at, now())`
		finishedExpr = `NULL`
	case "completed", "expired", "stopped", "failed":
		finishedExpr = `now()`
	}
	_, err := d.ExecContext(ctx, `UPDATE benchmark_sessions SET status=$2,last_error=$3,started_at=`+startedExpr+`,finished_at=`+finishedExpr+` WHERE id=$1`, id, status, lastError)
	return err
}

func (d *DB) UpdateBenchmarkSessionMaxConcurrent(ctx context.Context, id int64, maxConc int) error {
	if maxConc <= 0 {
		return nil
	}
	_, err := d.ExecContext(ctx, `UPDATE benchmark_sessions SET max_concurrent=$2 WHERE id=$1`, id, maxConc)
	return err
}

func (d *DB) DeleteBenchmarkSession(ctx context.Context, id int64) error {
	_, err := d.ExecContext(ctx, `DELETE FROM benchmark_sessions WHERE id=$1`, id)
	return err
}

func (d *DB) ListBenchmarkChallengeTaskIDs(ctx context.Context, sessionID int64) ([]int64, error) {
	rows, err := d.QueryContext(ctx, `SELECT DISTINCT id FROM tasks WHERE benchmark_session_id=$1 AND deleted_at IS NULL`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var tid int64
		if err := rows.Scan(&tid); err != nil {
			return nil, err
		}
		ids = append(ids, tid)
	}
	return ids, rows.Err()
}

type BenchmarkChallengeUpsert struct {
	UniqueCode       string
	Title            string
	Description      string
	Category         string
	Difficulty       string
	Level            int
	SubmissionType   string
	TotalScore       int
	CumulativeScore  int
	FlagCount        int
	CorrectFlagCount int
	IsCompleted      bool
	ContainerStatus  string
	ContainerAddr    []string
	Meta             json.RawMessage
}

func (d *DB) SyncBenchmarkChallenges(ctx context.Context, sessionID int64, items []BenchmarkChallengeUpsert) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, it := range items {
		if strings.TrimSpace(it.UniqueCode) == "" {
			continue
		}
		subType := strings.TrimSpace(it.SubmissionType)
		if subType == "" {
			subType = "flag"
		}
		flagCount := it.FlagCount
		if flagCount <= 0 {
			flagCount = 1
		}
		addrs, _ := json.Marshal(it.ContainerAddr)
		if len(it.ContainerAddr) == 0 {
			addrs = []byte("[]")
		}
		meta := it.Meta
		if len(meta) == 0 {
			meta = json.RawMessage(`{}`)
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO benchmark_challenges(session_id,unique_code,title,description,category,difficulty,level,submission_type,total_score,cumulative_score,flag_count,correct_flag_count,is_completed,container_status,container_addr,meta_json)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
ON CONFLICT (session_id, unique_code) DO UPDATE SET
  title = CASE WHEN EXCLUDED.title <> '' THEN EXCLUDED.title ELSE benchmark_challenges.title END,
  description = CASE WHEN EXCLUDED.description <> '' THEN EXCLUDED.description ELSE benchmark_challenges.description END,
  category = CASE WHEN EXCLUDED.category <> '' AND LOWER(EXCLUDED.category) <> 'auto' THEN EXCLUDED.category ELSE benchmark_challenges.category END,
  difficulty = CASE WHEN EXCLUDED.difficulty <> '' THEN EXCLUDED.difficulty ELSE benchmark_challenges.difficulty END,
  level = CASE WHEN EXCLUDED.level > 0 THEN EXCLUDED.level ELSE benchmark_challenges.level END,
  submission_type = EXCLUDED.submission_type,
  total_score = GREATEST(benchmark_challenges.total_score, EXCLUDED.total_score),
  cumulative_score = GREATEST(benchmark_challenges.cumulative_score, EXCLUDED.cumulative_score),
  flag_count = GREATEST(1, EXCLUDED.flag_count),
  correct_flag_count = GREATEST(benchmark_challenges.correct_flag_count, EXCLUDED.correct_flag_count),
  is_completed = benchmark_challenges.is_completed OR EXCLUDED.is_completed,
  container_status = CASE WHEN EXCLUDED.container_status IN ('available', 'pending') THEN EXCLUDED.container_status ELSE benchmark_challenges.container_status END,
  container_addr = CASE WHEN jsonb_array_length(EXCLUDED.container_addr) > 0 THEN EXCLUDED.container_addr ELSE benchmark_challenges.container_addr END,
  meta_json = CASE WHEN EXCLUDED.meta_json::text <> '{}' THEN EXCLUDED.meta_json ELSE benchmark_challenges.meta_json END`,
			sessionID, it.UniqueCode, it.Title, it.Description, it.Category, it.Difficulty, it.Level,
			subType, it.TotalScore, it.CumulativeScore, flagCount, it.CorrectFlagCount, it.IsCompleted,
			it.ContainerStatus, addrs, []byte(meta),
		); err != nil {
			return err
		}
	}
	if err := recomputeBenchmarkSessionAggregatesTx(ctx, tx, sessionID); err != nil {
		return err
	}
	return tx.Commit()
}

func recomputeBenchmarkSessionAggregatesTx(ctx context.Context, tx *sql.Tx, sessionID int64) error {
	_, err := tx.ExecContext(ctx, `
UPDATE benchmark_sessions SET
  total_score = COALESCE((SELECT SUM(cumulative_score) FROM benchmark_challenges WHERE session_id=$1), 0),
  max_possible_score = COALESCE((SELECT SUM(total_score) FROM benchmark_challenges WHERE session_id=$1), 0),
  completed_count = COALESCE((SELECT COUNT(*) FROM benchmark_challenges WHERE session_id=$1 AND is_completed=true), 0),
  total_count = COALESCE((SELECT COUNT(*) FROM benchmark_challenges WHERE session_id=$1), 0),
  active_slots = COALESCE((SELECT COUNT(*) FROM benchmark_challenges WHERE session_id=$1 AND container_status IN ('available','pending')), 0)
WHERE id=$1`, sessionID)
	return err
}

func (d *DB) RecomputeBenchmarkSessionAggregates(ctx context.Context, sessionID int64) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := recomputeBenchmarkSessionAggregatesTx(ctx, tx, sessionID); err != nil {
		return err
	}
	return tx.Commit()
}

const benchChallengeCols = `bc.id,bc.session_id,bc.unique_code,bc.title,bc.description,bc.category,bc.difficulty,bc.level,bc.submission_type,bc.total_score,bc.cumulative_score,bc.flag_count,bc.correct_flag_count,bc.is_completed,bc.container_status,bc.container_addr,bc.env_expires_at,bc.hint_used,bc.hint_content,bc.bound_task_id,COALESCE(t.status, ''),bc.attempt_count,bc.meta_json,bc.last_error,bc.created_at,bc.updated_at`
const benchChallengeFrom = `benchmark_challenges bc LEFT JOIN tasks t ON t.id = bc.bound_task_id AND t.deleted_at IS NULL`

func scanBenchmarkChallenge(sc interface{ Scan(...any) error }) (*BenchmarkChallenge, error) {
	var c BenchmarkChallenge
	var addrs, meta []byte
	if err := sc.Scan(
		&c.ID, &c.SessionID, &c.UniqueCode, &c.Title, &c.Description, &c.Category, &c.Difficulty, &c.Level,
		&c.SubmissionType, &c.TotalScore, &c.CumulativeScore, &c.FlagCount, &c.CorrectFlagCount, &c.IsCompleted,
		&c.ContainerStatus, &addrs, &c.EnvExpiresAt, &c.HintUsed, &c.HintContent, &c.BoundTaskID, &c.BoundTaskStatus,
		&c.AttemptCount, &meta, &c.LastError, &c.CreatedAt, &c.UpdatedAt,
	); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(addrs, &c.ContainerAddr)
	if c.ContainerAddr == nil {
		c.ContainerAddr = []string{}
	}
	if len(meta) == 0 {
		c.Meta = json.RawMessage(`{}`)
	} else {
		c.Meta = json.RawMessage(meta)
	}
	return &c, nil
}

func (d *DB) ListBenchmarkChallenges(ctx context.Context, sessionID int64) ([]*BenchmarkChallenge, error) {
	rows, err := d.QueryContext(ctx, `SELECT `+benchChallengeCols+` FROM `+benchChallengeFrom+` WHERE bc.session_id=$1 ORDER BY bc.is_completed ASC, bc.level ASC, bc.id ASC`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*BenchmarkChallenge{}
	for rows.Next() {
		c, err := scanBenchmarkChallenge(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (d *DB) GetBenchmarkChallenge(ctx context.Context, sessionID int64, uniqueCode string) (*BenchmarkChallenge, error) {
	c, err := scanBenchmarkChallenge(d.QueryRowContext(ctx, `SELECT `+benchChallengeCols+` FROM `+benchChallengeFrom+` WHERE bc.session_id=$1 AND bc.unique_code=$2`, sessionID, uniqueCode))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return c, err
}

func (d *DB) FindBenchmarkByTaskID(ctx context.Context, taskID int64) (*BenchmarkSession, *BenchmarkChallenge, error) {
	c, err := scanBenchmarkChallenge(d.QueryRowContext(ctx, `SELECT `+benchChallengeCols+` FROM `+benchChallengeFrom+` WHERE bc.bound_task_id=$1`, taskID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	s, err := d.GetBenchmarkSession(ctx, c.SessionID)
	if err != nil {
		return nil, nil, err
	}
	return s, c, nil
}

func (d *DB) BindBenchmarkChallengeTask(ctx context.Context, sessionID int64, uniqueCode string, taskID int64) error {
	_, err := d.ExecContext(ctx, `UPDATE benchmark_challenges SET bound_task_id=$3, attempt_count=attempt_count+1, last_error='' WHERE session_id=$1 AND unique_code=$2`, sessionID, uniqueCode, taskID)
	return err
}

// ResetBenchmarkChallengeForRetry clears an incomplete challenge's bound failed/interrupted
// task reference and resets attempt_count to 0 so the scheduler re-fetches full detail
// and re-queues it promptly.
func (d *DB) ResetBenchmarkChallengeForRetry(ctx context.Context, sessionID int64, uniqueCode string) error {
	_, err := d.ExecContext(ctx, `
UPDATE benchmark_challenges
SET bound_task_id = NULL,
    attempt_count = 0,
    last_error = '',
    container_status = 'stopped',
    container_addr = '[]'::jsonb,
    env_expires_at = NULL
WHERE session_id = $1 AND unique_code = $2 AND is_completed = false`, sessionID, uniqueCode)
	return err
}

// ResetFailedBenchmarkChallenges re-queues every incomplete challenge in sessionID whose
// bound sub-task already terminated (failed/stopped/cancelled/done) or vanished.
func (d *DB) ResetFailedBenchmarkChallenges(ctx context.Context, sessionID int64) (int64, error) {
	res, err := d.ExecContext(ctx, `
UPDATE benchmark_challenges bc
SET bound_task_id = NULL,
    attempt_count = 0,
    last_error = '',
    container_status = 'stopped',
    container_addr = '[]'::jsonb,
    env_expires_at = NULL
WHERE bc.session_id = $1
  AND bc.is_completed = false
  AND (
    bc.last_error <> ''
    OR (
      bc.bound_task_id IS NOT NULL
      AND COALESCE((SELECT t.status FROM tasks t WHERE t.id = bc.bound_task_id AND t.deleted_at IS NULL), 'failed')
          IN ('failed', 'stopped', 'cancelled', 'done', 'timeout')
    )
    OR (bc.bound_task_id IS NULL AND bc.attempt_count > 0)
  )`, sessionID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (d *DB) UpdateBenchmarkChallengeEnv(ctx context.Context, sessionID int64, uniqueCode, status string, addrs []string, expiresAt *time.Time, lastErr string) error {
	rawAddrs, _ := json.Marshal(addrs)
	if len(addrs) == 0 {
		rawAddrs = []byte("[]")
	}
	if _, err := d.ExecContext(ctx, `
UPDATE benchmark_challenges SET container_status=$3, container_addr=$4, env_expires_at=$5, last_error=$6
WHERE session_id=$1 AND unique_code=$2`, sessionID, uniqueCode, status, rawAddrs, expiresAt, lastErr); err != nil {
		return err
	}
	return d.RecomputeBenchmarkSessionAggregates(ctx, sessionID)
}

// ClearBenchmarkQuotaErrors wipes transient agent_environment_limit messages from
// challenges once a slot opens or a session resumes/reclaims leaked environments.
func (d *DB) ClearBenchmarkQuotaErrors(ctx context.Context, sessionID int64) error {
	_, err := d.ExecContext(ctx, `
UPDATE benchmark_challenges SET last_error = ''
WHERE session_id = $1 AND last_error ILIKE '%agent_environment_limit%'`, sessionID)
	return err
}

// ClearBenchmarkTransientErrors clears platform-wide maintenance, quota, or transient
// network error stamps so recovered sessions schedule affected challenges normally.
func (d *DB) ClearBenchmarkTransientErrors(ctx context.Context, sessionID int64) error {
	_, err := d.ExecContext(ctx, `
UPDATE benchmark_challenges SET last_error = ''
WHERE session_id = $1
  AND last_error <> ''
  AND (
    last_error ILIKE '%agent_environment_limit%'
    OR last_error ILIKE '%maintenance_mode%'
    OR last_error ILIKE '%server misbehaving%'
    OR last_error ILIKE '%dial tcp%'
    OR last_error ILIKE '%stream error%'
  )`, sessionID)
	return err
}

func (d *DB) UpdateBenchmarkChallengeProgress(ctx context.Context, sessionID int64, uniqueCode string, cumulativeScore, correctFlags, totalFlags int, completed bool) error {
	if _, err := d.ExecContext(ctx, `
UPDATE benchmark_challenges SET
  cumulative_score = GREATEST(cumulative_score, $3),
  correct_flag_count = GREATEST(correct_flag_count, $4),
  flag_count = GREATEST(1, flag_count, $5),
  is_completed = is_completed OR $6
WHERE session_id=$1 AND unique_code=$2`, sessionID, uniqueCode, cumulativeScore, correctFlags, totalFlags, completed); err != nil {
		return err
	}
	return d.RecomputeBenchmarkSessionAggregates(ctx, sessionID)
}

func (d *DB) SaveBenchmarkChallengeHint(ctx context.Context, sessionID int64, uniqueCode, hint string) error {
	_, err := d.ExecContext(ctx, `UPDATE benchmark_challenges SET hint_used=true, hint_content=$3 WHERE session_id=$1 AND unique_code=$2`, sessionID, uniqueCode, hint)
	return err
}

func (d *DB) UpdateBenchmarkChallengeMeta(ctx context.Context, sessionID int64, uniqueCode string, meta json.RawMessage) error {
	if len(meta) == 0 {
		return nil
	}
	_, err := d.ExecContext(ctx, `UPDATE benchmark_challenges SET meta_json=$3 WHERE session_id=$1 AND unique_code=$2`, sessionID, uniqueCode, []byte(meta))
	return err
}

func benchmarkAnswerHash(subFlagID, answer string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(subFlagID) + "\x00" + strings.TrimSpace(answer)))
	return hex.EncodeToString(sum[:])
}

func (d *DB) HasSubmittedBenchmarkAnswer(ctx context.Context, sessionID int64, uniqueCode, subFlagID, answer string) (bool, error) {
	var exists bool
	h := benchmarkAnswerHash(subFlagID, answer)
	// Ignore http_status = 0 rows caused by transient transport errors that never reached platform grading.
	err := d.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM benchmark_submissions WHERE session_id=$1 AND unique_code=$2 AND answer_sha256=$3 AND (http_status > 0 OR correct = true))`, sessionID, uniqueCode, h).Scan(&exists)
	return exists, err
}

func (d *DB) CountRejectedBenchmarkSubmissions(ctx context.Context, sessionID int64, uniqueCode string) (int, error) {
	var n int
	err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM benchmark_submissions WHERE session_id=$1 AND unique_code=$2 AND http_status > 0 AND correct = false`, sessionID, uniqueCode).Scan(&n)
	return n, err
}

func (d *DB) RecordBenchmarkSubmission(ctx context.Context, s BenchmarkSubmission) error {
	h := benchmarkAnswerHash(s.SubFlagID, s.AnswerValue)
	_, err := d.ExecContext(ctx, `
INSERT INTO benchmark_submissions(session_id,unique_code,sub_flag_id,answer_value,answer_sha256,correct,awarded,matched_flag_index,http_status,error_code,message)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		s.SessionID, s.UniqueCode, s.SubFlagID, s.AnswerValue, h, s.Correct, s.Awarded, s.MatchedFlagIndex, s.HTTPStatus, s.ErrorCode, s.Message)
	return err
}

func (d *DB) ListBenchmarkSubmissions(ctx context.Context, sessionID int64) ([]BenchmarkSubmission, error) {
	rows, err := d.QueryContext(ctx, `SELECT id,session_id,unique_code,sub_flag_id,answer_value,answer_sha256,correct,awarded,matched_flag_index,http_status,error_code,message,created_at FROM benchmark_submissions WHERE session_id=$1 ORDER BY id DESC LIMIT 500`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []BenchmarkSubmission{}
	for rows.Next() {
		var it BenchmarkSubmission
		if err := rows.Scan(&it.ID, &it.SessionID, &it.UniqueCode, &it.SubFlagID, &it.AnswerValue, &it.AnswerSHA256, &it.Correct, &it.Awarded, &it.MatchedFlagIndex, &it.HTTPStatus, &it.ErrorCode, &it.Message, &it.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

func (d *DB) AppendBenchmarkEvent(ctx context.Context, sessionID int64, uniqueCode, kind, summary string, detail any) error {
	raw := []byte("{}")
	if detail != nil {
		if b, err := json.Marshal(detail); err == nil {
			raw = b
		}
	}
	_, err := d.ExecContext(ctx, `INSERT INTO benchmark_events(session_id,unique_code,kind,summary,detail_json) VALUES ($1,$2,$3,$4,$5)`, sessionID, uniqueCode, kind, summary, raw)
	return err
}

func (d *DB) ListBenchmarkEvents(ctx context.Context, sessionID int64, limit int) ([]BenchmarkEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := d.QueryContext(ctx, `SELECT id,session_id,unique_code,kind,summary,detail_json,created_at FROM benchmark_events WHERE session_id=$1 ORDER BY id DESC LIMIT $2`, sessionID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []BenchmarkEvent{}
	for rows.Next() {
		var e BenchmarkEvent
		var detail []byte
		if err := rows.Scan(&e.ID, &e.SessionID, &e.UniqueCode, &e.Kind, &e.Summary, &detail, &e.CreatedAt); err != nil {
			return nil, err
		}
		if len(detail) == 0 {
			e.Detail = json.RawMessage(`{}`)
		} else {
			e.Detail = json.RawMessage(detail)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (d *DB) queryBenchmarkTokenMap(ctx context.Context, query string, args ...any) (map[int64]BenchmarkTokenUsage, error) {
	rows, err := d.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]BenchmarkTokenUsage{}
	for rows.Next() {
		var key int64
		var u BenchmarkTokenUsage
		if err := rows.Scan(&key, &u.InputTokens, &u.OutputTokens, &u.CacheReadTokens, &u.CacheWriteTokens); err != nil {
			return nil, err
		}
		u.TotalTokens = u.InputTokens + u.OutputTokens + u.CacheReadTokens + u.CacheWriteTokens
		out[key] = u
	}
	return out, rows.Err()
}

// PopulateBenchmarkSessionTokens fills Tokens for each session by aggregating
// activity result rows across all non-deleted sub-tasks bound to that session.
func (d *DB) PopulateBenchmarkSessionTokens(ctx context.Context, sessions []*BenchmarkSession) error {
	if len(sessions) == 0 {
		return nil
	}
	ids := make([]int64, 0, len(sessions))
	for _, s := range sessions {
		if s != nil && s.ID > 0 {
			ids = append(ids, s.ID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	totals, err := d.queryBenchmarkTokenMap(ctx, `
SELECT t.benchmark_session_id,
	COALESCE(SUM(a.input_tokens), 0),
	COALESCE(SUM(a.output_tokens), 0),
	COALESCE(SUM(a.cache_read_tokens), 0),
	COALESCE(SUM(a.cache_write_tokens), 0)
FROM tasks t
JOIN activity a ON a.exploration_id = t.exploration_id AND a.kind = 'result'
WHERE t.benchmark_session_id = ANY($1::bigint[])
  AND t.deleted_at IS NULL
GROUP BY t.benchmark_session_id`, formatPGInt64Array(ids))
	if err != nil {
		return err
	}
	for _, s := range sessions {
		if s != nil {
			s.Tokens = totals[s.ID]
		}
	}
	return nil
}

// PopulateBenchmarkChallengeTokens fills Tokens for each challenge in a session
// from the exploration activity of its bound sub-task.
func (d *DB) PopulateBenchmarkChallengeTokens(ctx context.Context, sessionID int64, challenges []*BenchmarkChallenge) error {
	if sessionID <= 0 || len(challenges) == 0 {
		return nil
	}
	totals, err := d.queryBenchmarkTokenMap(ctx, `
SELECT bc.id,
	COALESCE(SUM(a.input_tokens), 0),
	COALESCE(SUM(a.output_tokens), 0),
	COALESCE(SUM(a.cache_read_tokens), 0),
	COALESCE(SUM(a.cache_write_tokens), 0)
FROM benchmark_challenges bc
JOIN tasks t ON t.deleted_at IS NULL
  AND (t.id = bc.bound_task_id OR (t.benchmark_session_id = bc.session_id AND t.name LIKE '[' || bc.unique_code || '] %'))
JOIN activity a ON a.exploration_id = t.exploration_id AND a.kind = 'result'
WHERE bc.session_id = $1
GROUP BY bc.id`, sessionID)
	if err != nil {
		return err
	}
	for _, c := range challenges {
		if c != nil {
			c.Tokens = totals[c.ID]
		}
	}
	return nil
}
