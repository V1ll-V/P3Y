package server

import (
	"fmt"
	"strconv"

	"p3y/agent"
)

const verifierProfileSetting = "verification_model_profile_id"

func (s *Server) verifierProfileID() (*int64, error) {
	if s == nil || s.m == nil || s.m.pg == nil {
		return nil, nil
	}
	value, _, err := s.m.pg.GetSetting(verifierProfileSetting)
	if err != nil {
		return nil, err
	}
	if value == "" || value == "0" {
		return nil, nil
	}
	id, err := strconv.ParseInt(value, 10, 64)
	if err != nil || id <= 0 {
		return nil, fmt.Errorf("验收模型配置无效")
	}
	return &id, nil
}

// Goal evaluation follows the task's configured runtime unless a verifier was
// explicitly selected. Exhausted task chains must not fall through to global.
func (s *Server) verifierForTask(t *Task) agent.Verifier {
	s.cfgMu.Lock()
	injected := s.verifier
	s.cfgMu.Unlock()
	id, err := s.verifierProfileID()
	if injected != nil || id != nil || err != nil || t == nil {
		return s.currentVerifier()
	}
	if !s.taskRuntimeAvailable(t, "goals") {
		return nil
	}
	return &agent.LLMVerifier{Prov: &taskLLMRuntime{s: s, taskID: t.ID, agentKey: "goals"}}
}

