package db

import (
	"context"
	"database/sql"
	"errors"
)

// PendingCTFSubmission only considers undecided answers for the current input.
// Ordinary tasks, rejected answers and stale attachment snapshots never wait.
func (d *DB) PendingCTFSubmission(ctx context.Context, taskID int64) (*CTFCandidate, error) {
	c, err := scanCTFCandidate(d.QueryRowContext(ctx, `SELECT c.id,c.task_id,c.execution_id,c.input_hash,c.value,c.state,c.notes,c.revision,c.created_at,c.updated_at,c.kind
 FROM ctf_candidates c JOIN tasks t ON t.id=c.task_id
 WHERE t.id=$1 AND t.mode='ctf' AND t.deleted_at IS NULL
 AND c.input_hash=t.ctf_input_hash AND c.state='candidate' ORDER BY c.id DESC LIMIT 1`, taskID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// PendingCTFCandidateSummary returns the count and latest value of undecided CTF candidates
// for a non-terminal CTF task under its current input snapshot.
func (d *DB) PendingCTFCandidateSummary(ctx context.Context, taskID int64) (int, string, error) {
	var count int
	var latest string
	err := d.QueryRowContext(ctx, `
		SELECT COUNT(*), COALESCE((ARRAY_AGG(c.value ORDER BY c.id DESC))[1], '')
		FROM ctf_candidates c JOIN tasks t ON t.id=c.task_id
		WHERE t.id=$1 AND t.mode='ctf' AND t.deleted_at IS NULL
		  AND t.status NOT IN ('done', 'failed', 'timeout')
		  AND c.input_hash=t.ctf_input_hash AND c.state='candidate'`, taskID).Scan(&count, &latest)
	return count, latest, err
}
