package server

import (
	"context"
	"testing"

	"p3y/db"
)

func TestCreateGoalsNilTask(t *testing.T) {
	if got := (&Server{}).createGoals(context.Background(), nil, nil); len(got) != 0 {
		t.Fatalf("nil task produced goals: %+v", got)
	}
}

func TestCreateGoalsZeroTouchSkipsLLM(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { m.Close() })

	taskObj, err := m.CreateTaskWithOptions("bench-zero-touch", "获取全部 Flag 并提交验证", db.TaskCreateOptions{
		Mode:      "ctf",
		ZeroTouch: true,
	})
	if err != nil {
		t.Fatalf("CreateTaskWithOptions: %v", err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(taskObj.ID, DeleteTaskOptions{}) })

	// Even with nil engine (no LLM), ZeroTouch must directly materialize the single goal node.
	specs := (&Server{m: m}).createGoals(t.Context(), taskObj, nil)
	if len(specs) != 1 || specs[0].Text != "获取全部 Flag 并提交验证" {
		t.Fatalf("expected 1 deterministic zero-touch goal, got %+v", specs)
	}
	nodes, err := taskObj.Store.ListByKind(db.KindGoal, 10)
	if err != nil || len(nodes) != 1 {
		t.Fatalf("expected 1 persisted goal node, got %d (err=%v)", len(nodes), err)
	}
}
