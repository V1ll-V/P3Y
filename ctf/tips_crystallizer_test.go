package ctf

import (
	"os"
	"testing"

	"p3y/db"
)

func TestCrystallizeTipsDeterministicAndIdempotent(t *testing.T) {
	dsn := os.Getenv("P3Y_PG_DSN")
	if dsn == "" {
		t.Skip("test database required; set P3Y_PG_DSN")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()

	task, err := pg.CreateTaskWithOptions("stage5-tips-crystallizer", "solve pwn", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "pwn"})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)

	sp, err := pg.AddBoardItem(t.Context(), db.BoardItem{
		TaskID:   task.ID,
		Kind:     db.BoardKindSavepoint,
		Title:    "leak_verified",
		Summary:  "成功泄露 puts GOT 并算出 glibc 基址",
		Verified: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = pg.RecordRewindAndDeadend(t.Context(), task.ID, sp.ID, "no_ret_align", "直接跳 system 未加 ret 导致 MOVAPS 崩", "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = pg.UpsertBoardKit(t.Context(), db.BoardKit{
		TaskID:      task.ID,
		SavepointID: &sp.ID,
		Name:        "exp.py",
		Path:        "/work/exp.py",
		Summary:     "ret2libc with ret gadget",
		Verified:    true,
	})
	if err != nil {
		t.Fatal(err)
	}

	svc := New(t.TempDir(), pg)
	cards, err := svc.CrystallizeTips(t.Context(), task.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cards) == 0 {
		t.Fatal("expected at least 1 TipCard crystallized")
	}
	defer func() {
		for _, c := range cards {
			_ = pg.DeleteTipCard(t.Context(), c.ID)
		}
	}()
	if cards[0].SourceTaskID == nil || *cards[0].SourceTaskID != task.ID {
		t.Fatalf("expected source_task_id=%d, got %+v", task.ID, cards[0])
	}

	// Second call must be idempotent (returns existing crystallized cards, doesn't duplicate).
	cards2, err := svc.CrystallizeTips(t.Context(), task.ID, nil)
	if err != nil || len(cards2) != len(cards) || cards2[0].ID != cards[0].ID {
		t.Fatalf("expected idempotent crystallize, got %+v vs %+v (err=%v)", cards2, cards, err)
	}
}
