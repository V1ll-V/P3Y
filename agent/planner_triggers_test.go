package agent

import (
	"strings"
	"testing"
	"unicode/utf8"

	"p3y/db"
)

func TestFormatYieldedFactsInlineAndTruncation(t *testing.T) {
	if got := formatYieldedFacts(nil); got != "" {
		t.Fatalf("expected empty output for nil facts, got %q", got)
	}

	longSummary := strings.Repeat("字", 200)
	facts := []yieldedFact{
		{ID: 11, Summary: "  识别出   nginx + SSTI \n 入口  "},
		{ID: 12, Summary: longSummary},
		{ID: 13, Summary: ""},
		{ID: 14, Summary: "fact 4"},
		{ID: 15, Summary: "fact 5"},
		{ID: 16, Summary: "fact 6"},
		{ID: 17, Summary: "fact 7"},
	}

	got := formatYieldedFacts(facts)
	if !strings.Contains(got, "事实 #11：识别出 nginx + SSTI 入口") {
		t.Fatalf("expected whitespace-normalized inline fact #11, got:\n%s", got)
	}
	if strings.Contains(got, longSummary) {
		t.Fatalf("expected >160 rune summary to be truncated, got:\n%s", got)
	}
	// Line for #12 should be truncated to 160 runes + ellipsis.
	for _, line := range strings.Split(strings.TrimSpace(got), "\n") {
		if strings.Contains(line, "事实 #12：") {
			parts := strings.SplitN(line, "事实 #12：", 2)
			if utf8.RuneCountInString(parts[1]) != 161 || !strings.HasSuffix(parts[1], "…") {
				t.Fatalf("unexpected truncated rune count (%d): %q", utf8.RuneCountInString(parts[1]), parts[1])
			}
		}
	}
	if !strings.Contains(got, "事实 #13\n") {
		t.Fatalf("expected bare ID fallback for empty summary, got:\n%s", got)
	}
	if strings.Contains(got, "fact 6") || strings.Contains(got, "fact 7") {
		t.Fatalf("facts beyond 5 must not be inlined, got:\n%s", got)
	}
	if !strings.Contains(got, "其余新事实 id：#16、#17") {
		t.Fatalf("expected trailing ID list for facts > 5, got:\n%s", got)
	}
}

func TestRenderTriggersInlinesYieldedFactSummaries(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("test database required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()

	task, err := pg.CreateTaskWithOptions("planner-trigger-facts", "goal", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "web"})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)

	es := pg.Exploration(task.ExplorationID)
	intentID, err := es.AddIntent(map[string]any{"summary": "probe web"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	factID, err := es.AddNode(db.KindFact, map[string]any{"summary": "发现 /admin 未鉴权读取接口"}, 5, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := es.Link(intentID, db.RelYields, factID); err != nil {
		t.Fatal(err)
	}

	out := renderTriggers(es, []TriggerEvent{{Kind: "done", IntentID: intentID}})
	if !strings.Contains(out, "发现 /admin 未鉴权读取接口") || !strings.Contains(out, "事实 #") {
		t.Fatalf("expected renderTriggers to inline yielded fact summary (fact #%d), got:\n%s", factID, out)
	}
}
