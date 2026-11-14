package server

import (
	"fmt"
	"testing"

	"p3y/agent"
	"p3y/db"
)

func TestGoalVerifierInheritsTaskModelAndHonorsExhaustedChain(t *testing.T) {
	s := &Server{m: &Manager{pg: privateVerificationDB(t), dir: t.TempDir()}, ctx: t.Context()}
	id, err := s.m.pg.SaveProfile(&db.LLMProfile{Name: "task-only verifier fixture", Format: "openai", Model: "local", APIKey: "fake-key-never-sent"})
	if err != nil {
		t.Fatal(err)
	}
	provider := &verificationInputProvider{}
	s.provByProfile = map[int64]*provEntry{id: {prov: provider}}
	task := &Task{ID: "task-model-fixture", LLMProfileIDs: []int64{id}, ActiveLLMProfileID: &id}
	v, ok := s.verifierForTask(task).(*agent.LLMVerifier)
	if !ok {
		t.Fatal("task-only model could not provide goal verification")
	}
	if runtime, ok := v.Prov.(*taskLLMRuntime); !ok || runtime.taskID != task.ID {
		t.Fatal("goal verification bypassed task routing")
	}
	task.ActiveLLMProfileID = nil
	s.llmProv, s.llmOn = provider, true
	if s.verifierForTask(task) != nil {
		t.Fatal("exhausted task chain silently fell through to the global model")
	}
	if err = s.m.pg.SetSetting(verifierProfileSetting, fmt.Sprint(id)); err != nil {
		t.Fatal(err)
	}
	if explicit, ok := s.verifierForTask(task).(*agent.LLMVerifier); !ok || explicit.Prov != provider {
		t.Fatal("explicit verifier model ignored")
	}
	if provider.calls != 0 {
		t.Fatal("model resolution unexpectedly made a request")
	}
}
