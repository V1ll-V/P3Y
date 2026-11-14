package server

import (
	"context"
	"errors"
	"iter"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"p3y/agent"
	"p3y/db"
	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
)

type retestProvider struct {
	complete func(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error)
}

func (p retestProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return p.complete(ctx, req)
}

func (p retestProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		yield(llm.StreamEvent{}, errors.New("test expects non-streaming"))
	}
}

func newRetestServer(t *testing.T) (*Server, int64) {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("test postgres not configured")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	td := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{ctx: ctx, m: &Manager{pg: pg, dir: td, tasks: map[string]*Task{}},
		chatBusy: map[string]bool{}, chatCancel: map[string]context.CancelCauseFunc{}}
	fid, err := pg.AddFinding(0, 0, "retest-server", "测试发现", "high", "summary", "original proof", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	oldAugment, oldResolve, oldPrompt := agent.ToolAugment, agent.ToolResolve, agent.PromptOverride
	agent.ToolAugment = func(context.Context, string) ([]actool.CoreTool, agent.DeferredInfo, func()) {
		return nil, agent.DeferredInfo{}, func() {}
	}
	agent.ToolResolve = nil
	t.Cleanup(func() {
		cancel()
		waitRetestIdle(t, s)
		agent.ToolAugment, agent.ToolResolve, agent.PromptOverride = oldAugment, oldResolve, oldPrompt
		_, _ = pg.DeleteFinding(fid)
		pg.Close()
	})
	return s, fid
}

func setRetestProvider(s *Server, p retestProvider) {
	s.chatAgent = agent.NewChatAgent(p, "test", s.m.dir, nil, 10000)
	s.chatAgent.SetNonStreaming(func() bool { return true })
}

func retestRequest(handler http.HandlerFunc, method string, id int64, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "/", strings.NewReader(body))
	r.SetPathValue("id", strconv.FormatInt(id, 10))
	w := httptest.NewRecorder()
	handler(w, r)
	return w
}

func waitRetestIdle(t *testing.T, s *Server) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s.chatMu.Lock()
		n := len(s.chatBusy)
		s.chatMu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("conversation did not become idle")
}

// acceptedReportContext builds a persisted report-run context for traffic/export tests.
func acceptedReportContext(t *testing.T, s *Server, findingID int64) context.Context {
	t.Helper()
	ctx := t.Context()
	pg := s.m.pg
	if _, _, _, err := pg.SetFindingStatusWithNotify(ctx, findingID, db.FindingConfirmed); err != nil {
		t.Fatal(err)
	}
	if _, _, err := pg.FanOutVerdictEvents(ctx, 1000); err != nil {
		t.Fatal(err)
	}
	job, err := pg.ClaimEventJob(ctx, db.EventJobReportRun, time.Minute)
	if err != nil || job == nil {
		t.Fatal(job, err)
	}
	run, err := pg.PrepareReportRun(ctx, job.ID, job.LeaseGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if run.Snapshot.FindingID != findingID {
		t.Fatal("claimed another finding", run.Snapshot.FindingID, findingID)
	}
	if err = s.evidenceStore().LoadVerificationBodies(ctx, run.Snapshot.Evidence); err != nil {
		t.Fatal(err)
	}
	if _, err = pg.RecordReportExecutionInput(ctx, run, &db.ReportExecutionInput{Snapshot: run.Snapshot, SystemPrompt: "local fixture"}); err != nil {
		t.Fatal(err)
	}
	return db.WithReportRun(ctx, run)
}
