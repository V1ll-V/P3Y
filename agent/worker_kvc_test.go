package agent

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"p3y/db"
	"github.com/Autumn-27/norma/llm"
)

func TestWorkerSystemPromptStaticAcrossIntentsAndTasks(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("test database required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()

	t.Run("ctf_worker_system_byte_identical", func(t *testing.T) {
		task, err := pg.CreateTaskWithOptions("kvc-ctf", "find flag", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "pwn"})
		if err != nil {
			t.Fatal(err)
		}
		defer pg.DeleteTask(task.ID)

		ts := pg.Exploration(task.ExplorationID)
		i1ID, err := ts.AddIntent(map[string]any{"summary": "recon elf protections", "phase": "recon"}, 5, nil, "planner")
		if err != nil {
			t.Fatal(err)
		}
		i2ID, err := ts.AddIntent(map[string]any{"summary": "write ret2libc exploit", "phase": "exploit"}, 5, nil, "planner")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := NewToolSet(ts, "goals").setConstraints().Call(t.Context(), json.RawMessage(`{"type":"deny","text":"禁止访问外网端口 22"}`), nil); err != nil {
			t.Fatal(err)
		}

		p := &taskInputProbeProvider{captureUsageProvider: captureUsageProvider{stream: func(_ context.Context, y func(llm.StreamEvent, error) bool) {
			if y(llm.StreamEvent{Type: llm.SETextDelta, Text: "done"}, nil) {
				y(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "end_turn"}, nil)
			}
		}}}
		w := NewWorker(p, "test-model", t.TempDir(), nil, 0, 2)

		i1, _ := ts.GetNode(i1ID)
		i2, _ := ts.GetNode(i2ID)
		if _, _, err := w.Execute(t.Context(), "work-1", task.ID, nil, ts, i1, nil, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
		if _, _, err := w.Execute(t.Context(), "work-2", task.ID, nil, ts, i2, nil, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
		if len(p.requests) != 2 {
			t.Fatalf("expected 2 requests, got %d", len(p.requests))
		}
		if !reflect.DeepEqual(p.requests[0].System, p.requests[1].System) {
			t.Fatalf("CTF worker SystemPrompt changed between intents:\nfirst:  %q\nsecond: %q", p.requests[0].System, p.requests[1].System)
		}
		// Dynamic context must reside in initial User message instead.
		msg1 := allMessagesText(p.requests[0].Messages)
		msg2 := allMessagesText(p.requests[1].Messages)
		if !strings.Contains(msg1, "recon elf protections") || !strings.Contains(msg1, "RECON-ONLY") || !strings.Contains(msg1, "禁止访问外网端口 22") {
			t.Fatalf("first intent user message missing dynamic context: %s", msg1)
		}
		if !strings.Contains(msg2, "write ret2libc exploit") || strings.Contains(msg2, "RECON-ONLY") {
			t.Fatalf("second intent user message missing phase/task switch: %s", msg2)
		}
	})

	t.Run("pentest_worker_system_byte_identical", func(t *testing.T) {
		task, err := pg.CreateTaskWithOptions("kvc-pentest", "scan target", db.TaskCreateOptions{Mode: "pentest"})
		if err != nil {
			t.Fatal(err)
		}
		defer pg.DeleteTask(task.ID)

		ts := pg.Exploration(task.ExplorationID)
		i1ID, err := ts.AddIntent(map[string]any{"summary": "enum /api endpoints"}, 5, nil, "planner")
		if err != nil {
			t.Fatal(err)
		}
		i2ID, err := ts.AddIntent(map[string]any{"summary": "test idor on /api/users"}, 5, nil, "planner")
		if err != nil {
			t.Fatal(err)
		}

		p := &taskInputProbeProvider{captureUsageProvider: captureUsageProvider{stream: func(_ context.Context, y func(llm.StreamEvent, error) bool) {
			if y(llm.StreamEvent{Type: llm.SETextDelta, Text: "done"}, nil) {
				y(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "end_turn"}, nil)
			}
		}}}
		root := t.TempDir()
		w := NewWorker(p, "test-model", root, nil, 0, 2)
		w.SetProxy("127.0.0.1:8080", filepath.Join(root, "ca.pem"))

		i1, _ := ts.GetNode(i1ID)
		i2, _ := ts.GetNode(i2ID)
		if _, _, err := w.Execute(t.Context(), "work-1", task.ID, nil, ts, i1, nil, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
		if _, _, err := w.Execute(t.Context(), "work-2", task.ID, nil, ts, i2, nil, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
		if len(p.requests) != 2 {
			t.Fatalf("expected 2 requests, got %d", len(p.requests))
		}
		if !reflect.DeepEqual(p.requests[0].System, p.requests[1].System) {
			t.Fatalf("pentest worker SystemPrompt changed between intents:\nfirst:  %q\nsecond: %q", p.requests[0].System, p.requests[1].System)
		}
		msg1 := allMessagesText(p.requests[0].Messages)
		msg2 := allMessagesText(p.requests[1].Messages)
		if !strings.Contains(msg1, "enum /api endpoints") || !strings.Contains(msg1, "i"+jsonNumber(i1ID)) {
			t.Fatalf("intent 1 user message missing dynamic runDir/summary: %s", msg1)
		}
		if !strings.Contains(msg2, "test idor on /api/users") || !strings.Contains(msg2, "i"+jsonNumber(i2ID)) {
			t.Fatalf("intent 2 user message missing dynamic runDir/summary: %s", msg2)
		}
	})
}

func TestFormatCTFRejectionFeedbackUnified(t *testing.T) {
	flagMsg := formatCTFRejectionFeedback(db.CTFCandidate{Kind: db.CTFCandidateFlag, Value: "flag{wrong}", Notes: "wrong hash"})
	if !strings.Contains(flagMsg, "候选 Flag") || !strings.Contains(flagMsg, "wrong hash") {
		t.Fatalf("unexpected flag rejection feedback: %q", flagMsg)
	}
	proofMsg := formatCTFRejectionFeedback(db.CTFCandidate{Kind: db.CTFCandidateExploitProof, Value: "pwned_proof", Notes: ""})
	if !strings.Contains(proofMsg, "漏洞利用证明候选") || !strings.Contains(proofMsg, "备注：无") {
		t.Fatalf("unexpected exploit proof rejection feedback: %q", proofMsg)
	}
}

func jsonNumber(v int64) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func allMessagesText(msgs []llm.Message) string {
	var b strings.Builder
	for _, m := range msgs {
		for _, blk := range m.Content {
			if blk.Text != "" {
				b.WriteString(blk.Text)
				b.WriteByte('\n')
			}
		}
	}
	return b.String()
}
