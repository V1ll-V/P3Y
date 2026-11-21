package ctf

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// CheckResult holds the deterministic 0-LLM verification outcome for a savepoint or kit.
type CheckResult struct {
	Passed        bool   `json:"passed"`
	ExitCode      int    `json:"exit_code"`
	Command       string `json:"command"`
	ExecutionID   string `json:"execution_id,omitempty"`
	StdoutExcerpt string `json:"stdout_excerpt,omitempty"`
	StderrExcerpt string `json:"stderr_excerpt,omitempty"`
	Error         string `json:"error,omitempty"`
}

// VerifyCheck executes checkCmd inside the task sandbox as a deterministic 0-LLM oracle.
// ExitCode == 0 with no runner execution error counts as passed.
func (s *Service) VerifyCheck(ctx context.Context, task, intent int64, checkCmd string, timeoutSec int) (*CheckResult, error) {
	if s == nil {
		return nil, fmt.Errorf("需要 CTF 上下文")
	}
	cmd := strings.TrimSpace(checkCmd)
	if cmd == "" {
		return nil, fmt.Errorf("check_cmd 不能为空")
	}
	if timeoutSec <= 0 || timeoutSec > 180 {
		timeoutSec = 60
	}
	ex, err := s.Execute(ctx, task, intent, cmd, timeoutSec)
	if err != nil {
		return nil, err
	}
	res := &CheckResult{
		Passed:        ex.ExitCode == 0 && strings.TrimSpace(ex.Error) == "",
		ExitCode:      ex.ExitCode,
		Command:       cmd,
		ExecutionID:   ex.ID,
		StdoutExcerpt: ex.StdoutExcerpt,
		StderrExcerpt: ex.StderrExcerpt,
		Error:         ex.Error,
	}
	return res, nil
}

func (s *Service) readWorkspaceFile(ctx context.Context, task, intent int64, containerPath string) ([]byte, bool) {
	if s == nil || s.Root == "" {
		return nil, false
	}
	clean := path.Clean(strings.TrimSpace(containerPath))
	if !strings.HasPrefix(clean, "/work/") {
		return nil, false
	}
	rel := strings.TrimPrefix(clean, "/work/")
	if strings.HasPrefix(rel, ".inputs/") || strings.Contains(rel, "..") {
		return nil, false
	}
	workDir := s.EffectiveWorkDir(ctx, task, intent)
	hostPath := filepath.Join(workDir, filepath.FromSlash(rel))
	data, err := os.ReadFile(hostPath)
	if err != nil {
		return nil, false
	}
	return data, true
}

// ComputeWorkspaceFileSHA256 resolves a /work/... path to the task workspace on host
// (when available) and computes its SHA-256 hex digest without launching a container command.
func (s *Service) ComputeWorkspaceFileSHA256(ctx context.Context, task, intent int64, containerPath string) string {
	data, ok := s.readWorkspaceFile(ctx, task, intent, containerPath)
	if !ok {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ReadWorkspaceFileSnapshot computes the full SHA-256 digest of a /work/... file
// and returns up to maxBytes (default 128 KiB) of valid UTF-8 text when non-binary.
func (s *Service) ReadWorkspaceFileSnapshot(ctx context.Context, task, intent int64, containerPath string, maxBytes int) (sha, content string) {
	data, ok := s.readWorkspaceFile(ctx, task, intent, containerPath)
	if !ok {
		return "", ""
	}
	sum := sha256.Sum256(data)
	sha = hex.EncodeToString(sum[:])
	if maxBytes <= 0 {
		maxBytes = 128 * 1024
	}
	sample := data
	if len(sample) > maxBytes {
		sample = sample[:maxBytes]
	}
	if bytes.IndexByte(sample, 0) >= 0 {
		return sha, ""
	}
	if len(data) <= maxBytes {
		return sha, strings.ToValidUTF8(string(data), "")
	}
	for len(sample) > 0 && !utf8.Valid(sample) {
		if utf8.FullRune(sample[max(0, len(sample)-4):]) {
			break
		}
		sample = sample[:len(sample)-1]
	}
	return sha, strings.ToValidUTF8(string(sample), "") + fmt.Sprintf("\n# ... [已截断：原文件共 %d 字节，仅保留前 %d 字节]\n", len(data), len(sample))
}
