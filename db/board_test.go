package db

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestBoardItemsKitsPrecheckAndTipsStore(t *testing.T) {
	dsn, _, err := DSN()
	if err != nil {
		t.Skip("test database required")
	}
	pg, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()

	ctx := context.Background()
	task, err := pg.CreateTaskWithOptions("stage3-board", "exploit target", TaskCreateOptions{Mode: "ctf", ChallengeType: "pwn"})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)

	// 1. Precheck persistence
	rawPrecheck := json.RawMessage(`{"challenge_type":"pwn","tags":["elf","amd64","no_pie"]}`)
	if err := pg.SaveTaskPrecheck(ctx, task.ID, rawPrecheck); err != nil {
		t.Fatal(err)
	}
	gotPre, err := pg.TaskPrecheck(ctx, task.ID)
	if err != nil || !strings.Contains(string(gotPre), "no_pie") {
		t.Fatalf("TaskPrecheck=%s err=%v", gotPre, err)
	}

	// 2. 3-tier BoardItem + Savepoint + Rewind + Deadend
	sp, err := pg.AddBoardItem(ctx, BoardItem{
		TaskID:     task.ID,
		Kind:       BoardKindSavepoint,
		Title:      "libc leaked",
		Summary:    "leaked glibc 2.31 base address",
		Detail:     "full leak trace 0x7f1234000000",
		SnapshotID: "sp-100",
		CheckCmd:   "python3 /work/leak.py LOCAL",
		Verified:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	deadend, rwCount, err := pg.RecordRewindAndDeadend(ctx, task.ID, sp.ID, "one_gadget failed", "rsp+0x30 not null", "gdb trace...")
	if err != nil {
		t.Fatal(err)
	}
	if rwCount != 1 || deadend.ParentID == nil || *deadend.ParentID != sp.ID {
		t.Fatalf("unexpected deadend/rewind: rw=%d deadend=%+v", rwCount, deadend)
	}

	// 3. BoardKit upsert
	spID := sp.ID
	kit, err := pg.UpsertBoardKit(ctx, BoardKit{
		TaskID:      task.ID,
		SavepointID: &spID,
		Name:        "interact.py",
		Path:        "/work/interact.py",
		Summary:     "menu helper v1",
		SHA256:      "abc",
		Verified:    false,
	})
	if err != nil {
		t.Fatal(err)
	}
	kit2, err := pg.UpsertBoardKit(ctx, BoardKit{
		TaskID:      task.ID,
		SavepointID: &spID,
		Name:        "interact.py",
		Path:        "/work/interact.py",
		Summary:     "menu helper v2",
		SHA256:      "def",
		Verified:    true,
	})
	if err != nil || kit2.ID != kit.ID || !kit2.Verified || kit2.Summary != "menu helper v2" {
		t.Fatalf("kit upsert mismatch: first=%+v second=%+v err=%v", kit, kit2, err)
	}

	// 4. Compact L1/L2 overview must omit L3 Detail!
	digest := pg.RenderBoardIndex(ctx, task.ID)
	if !strings.Contains(digest, "libc leaked") || !strings.Contains(digest, "[detail#") || !strings.Contains(digest, "interact.py") {
		t.Fatalf("missing expected entries in board digest:\n%s", digest)
	}
	if strings.Contains(digest, "full leak trace 0x7f1234000000") || strings.Contains(digest, "gdb trace...") {
		t.Fatalf("L3 detail leaked into L1/L2 board index:\n%s", digest)
	}

	// 5. Tips Store seed & tag recall
	if err := pg.SeedDefaultTips(ctx); err != nil {
		t.Fatal(err)
	}
	matched, err := pg.SearchTips(ctx, "pwn", []string{"amd64", "stack_alignment"}, 3)
	if err != nil || len(matched) == 0 || !strings.Contains(matched[0].Title, "栈 16 字节对齐") {
		t.Fatalf("unexpected tips recall: matched=%+v err=%v", matched, err)
	}
}
