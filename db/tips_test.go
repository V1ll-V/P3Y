package db

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestTipsBayesianRankingAndTaskDedup(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	ctx := context.Background()
	var tasks []*Task
	for i := 0; i < 6; i++ {
		tk, err := d.CreateTaskWithOptions("tips-bayesian-test", "solve", TaskCreateOptions{Mode: "ctf", ChallengeType: "web"})
		if err != nil {
			t.Fatal(err)
		}
		tasks = append(tasks, tk)
		id := tk.ID
		t.Cleanup(func() { _ = d.DeleteTask(id) })
	}

	tag := fmt.Sprintf("bayesian-test-%d", time.Now().UnixNano())
	proven, err := d.CreateTipCard(ctx, TipCard{
		Category: "web",
		Tags:     []string{tag},
		Title:    "Proven Card",
		Pitfall:  "Proven pitfall",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTipCard(context.Background(), proven.ID) })

	fresh, err := d.CreateTipCard(ctx, TipCard{
		Category: "web",
		Tags:     []string{tag},
		Title:    "Fresh Card",
		Pitfall:  "Fresh pitfall",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTipCard(context.Background(), fresh.ID) })

	noisy, err := d.CreateTipCard(ctx, TipCard{
		Category: "web",
		Tags:     []string{tag},
		Title:    "Noisy Card",
		Pitfall:  "Noisy pitfall",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTipCard(context.Background(), noisy.ID) })

	// Same task hitting proven card twice must deduplicate hit_count=1.
	if err := d.RecordTaskTipHit(ctx, tasks[0].ID, proven.ID); err != nil {
		t.Fatal(err)
	}
	if err := d.RecordTaskTipHit(ctx, tasks[0].ID, proven.ID); err != nil {
		t.Fatal(err)
	}
	// Completing tasks[0] twice must deduplicate solve_count=1.
	if err := d.MarkTaskTipsSolved(ctx, tasks[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := d.MarkTaskTipsSolved(ctx, tasks[0].ID); err != nil {
		t.Fatal(err)
	}

	// Hit noisy across 5 unresolved tasks -> hit_count=5, solve_count=0 -> penalized.
	for i := 1; i <= 5; i++ {
		if err := d.RecordTaskTipHit(ctx, tasks[i].ID, noisy.ID); err != nil {
			t.Fatal(err)
		}
	}

	var provenHits, provenSolves, noisyHits, noisySolves int64
	if err := d.QueryRowContext(ctx, `SELECT hit_count, solve_count FROM tips_cards WHERE id=$1`, proven.ID).Scan(&provenHits, &provenSolves); err != nil {
		t.Fatal(err)
	}
	if provenHits != 1 || provenSolves != 1 {
		t.Fatalf("expected proven hit_count=1 solve_count=1, got hits=%d solves=%d", provenHits, provenSolves)
	}
	if err := d.QueryRowContext(ctx, `SELECT hit_count, solve_count FROM tips_cards WHERE id=$1`, noisy.ID).Scan(&noisyHits, &noisySolves); err != nil {
		t.Fatal(err)
	}
	if noisyHits != 5 || noisySolves != 0 {
		t.Fatalf("expected noisy hit_count=5 solve_count=0, got hits=%d solves=%d", noisyHits, noisySolves)
	}

	got, err := d.SearchTips(ctx, "", []string{tag}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 matched tips, got %d: %+v", len(got), got)
	}
	if got[0].ID != proven.ID || got[1].ID != fresh.ID || got[2].ID != noisy.ID {
		t.Fatalf("unexpected ranking order: got [%s(h=%d,s=%d), %s(h=%d,s=%d), %s(h=%d,s=%d)]",
			got[0].Title, got[0].HitCount, got[0].SolveCount,
			got[1].Title, got[1].HitCount, got[1].SolveCount,
			got[2].Title, got[2].HitCount, got[2].SolveCount)
	}

	catGot, err := d.SearchTips(ctx, "web", []string{tag}, 20)
	if err != nil {
		t.Fatal(err)
	}
	pos := map[int64]int{}
	for i, c := range catGot {
		pos[c.ID] = i
	}
	if !(pos[proven.ID] < pos[fresh.ID] && pos[fresh.ID] < pos[noisy.ID]) {
		t.Fatalf("expected proven < fresh < noisy under web category search, got positions %+v", pos)
	}
}

func TestNormalizeThinkingConfigAndAgentPersistence(t *testing.T) {
	if tt, re := NormalizeThinkingConfig("ENABLED", "Medium"); tt != "enabled" || re != "medium" {
		t.Fatalf("unexpected normalized enabled/medium: tt=%q re=%q", tt, re)
	}
	if tt, re := NormalizeThinkingConfig("disabled", "high"); tt != "disabled" || re != "high" {
		t.Fatalf("expected decoupled disabled/high normalization, got tt=%q re=%q", tt, re)
	}
	if tt, re := NormalizeThinkingConfig("invalid", "turbo"); tt != "" || re != "" {
		t.Fatalf("expected invalid thinking_type/effort to normalize to empty, got tt=%q re=%q", tt, re)
	}

	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	wantDefaults := map[string][2]string{
		"worker_recon": {"disabled", ""},
		"helper":       {"disabled", ""},
		"plateau_fork": {"enabled", "medium"},
		"critic":       {"enabled", "high"},
	}
	for name, want := range wantDefaults {
		ag, err := d.GetAgentByKey(name)
		if err != nil {
			t.Fatalf("GetAgentByKey(%q) error: %v", name, err)
		}
		if ag == nil {
			t.Fatalf("GetAgentByKey(%q) not seeded", name)
		}
		if ag.ThinkingType != want[0] || ag.ReasoningEffort != want[1] {
			t.Logf("note: agent %q current (%q/%q) vs seeded default (%q/%q)", name, ag.ThinkingType, ag.ReasoningEffort, want[0], want[1])
		}
	}

	orig, err := d.GetAgentByKey("critic")
	if err != nil || orig == nil {
		t.Fatalf("load critic failed: %v", err)
	}
	t.Cleanup(func() {
		_ = d.SetAgentThinking("critic", orig.ThinkingType, orig.ReasoningEffort)
	})
	if err := d.SetAgentThinking("critic", "enabled", "low"); err != nil {
		t.Fatal(err)
	}
	updated, err := d.GetAgentByKey("critic")
	if err != nil {
		t.Fatal(err)
	}
	if updated.ThinkingType != "enabled" || updated.ReasoningEffort != "low" {
		t.Fatalf("expected updated critic enabled/low, got %q/%q", updated.ThinkingType, updated.ReasoningEffort)
	}
}
