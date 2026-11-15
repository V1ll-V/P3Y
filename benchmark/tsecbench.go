package benchmark

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TSecBenchClient implements Provider for CHALLENGES_API.md (/openapi/v1/challenges/*).
type TSecBenchClient struct {
	baseURL string
	token   string
	http    *http.Client
}

func NewTSecBenchClient(baseURL, token string) *TSecBenchClient {
	return &TSecBenchClient{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		token:   strings.TrimSpace(token),
		http:    &http.Client{Timeout: 45 * time.Second},
	}
}

func (c *TSecBenchClient) Kind() string { return "tsecbench" }

func (c *TSecBenchClient) WhoAmI(ctx context.Context) (*AgentProfile, error) {
	// Validate credentials & connectivity via GET /openapi/v1/challenges.
	items, err := c.ListChallenges(ctx, SessionConfig{})
	if err != nil {
		return nil, err
	}
	return &AgentProfile{
		AgentName:          "tsecbench-runner",
		MaxEnvironments:    3,
		CompetitionEnabled: true,
		ActiveCompetitions: []string{fmt.Sprintf("%d challenges", len(items))},
	}, nil
}

type tsecChallengeDTO struct {
	UniqueCode       string   `json:"unique_code"`
	Description      *string  `json:"description"`
	Difficulty       string   `json:"difficulty"`
	Level            int      `json:"level"`
	TotalScore       int      `json:"total_score"`
	FlagCount        int      `json:"flag_count"`
	CorrectFlagCount int      `json:"correct_flag_count"`
	IsCompleted      bool     `json:"is_completed"`
	ContainerStatus  string   `json:"container_status"`
	ContainerAddr    []string `json:"container_addr"`
}

func (c *TSecBenchClient) ListChallenges(ctx context.Context, _ SessionConfig) ([]ChallengeSpec, error) {
	var raw []tsecChallengeDTO
	if _, err := c.doJSON(ctx, http.MethodGet, "/openapi/v1/challenges", nil, &raw); err != nil {
		return nil, err
	}
	out := make([]ChallengeSpec, 0, len(raw))
	for _, it := range raw {
		desc := ""
		if it.Description != nil {
			desc = *it.Description
		}
		cat := InferChallengeType(it.UniqueCode, "", desc)
		subType := "flag"
		flagCnt := it.FlagCount
		if flagCnt <= 0 {
			flagCnt = 1
		}
		out = append(out, ChallengeSpec{
			UniqueCode:       it.UniqueCode,
			Title:            it.UniqueCode,
			Description:      desc,
			Category:         cat,
			Difficulty:       it.Difficulty,
			Level:            it.Level,
			SubmissionType:   subType,
			TotalScore:       it.TotalScore,
			FlagCount:        flagCnt,
			CorrectFlagCount: it.CorrectFlagCount,
			IsCompleted:      it.IsCompleted,
			ContainerStatus:  it.ContainerStatus,
			ContainerAddr:    it.ContainerAddr,
			HasContainer:     true,
		})
	}
	return out, nil
}

func (c *TSecBenchClient) GetChallengeDetail(ctx context.Context, challengeID string) (*ChallengeSpec, error) {
	items, err := c.ListChallenges(ctx, SessionConfig{})
	if err != nil {
		return nil, err
	}
	for i := range items {
		if items[i].UniqueCode == challengeID {
			return &items[i], nil
		}
	}
	return nil, &StructuredError{HTTPStatus: 404, Code: "challenge_not_found", Message: "challenge not found: " + challengeID}
}

func (c *TSecBenchClient) DownloadAttachment(_ context.Context, _, _ string) (string, []byte, error) {
	return "", nil, errors.New("TSecBench 接口不提供题目附件下载")
}

func (c *TSecBenchClient) StartEnvironment(ctx context.Context, challengeID string) (*EnvState, error) {
	var resp struct {
		UniqueCode    string   `json:"unique_code"`
		ContainerAddr []string `json:"container_addr"`
	}
	path := "/openapi/v1/challenges/start?unique_code=" + url.QueryEscape(challengeID)
	if _, err := c.doJSON(ctx, http.MethodPost, path, nil, &resp); err != nil {
		return nil, err
	}
	status := "pending"
	if len(resp.ContainerAddr) > 0 {
		status = "available"
	}
	return &EnvState{
		UniqueCode: challengeID,
		Status:     status,
		Addrs:      resp.ContainerAddr,
	}, nil
}

func (c *TSecBenchClient) GetEnvironment(ctx context.Context, challengeID string) (*EnvState, error) {
	ch, err := c.GetChallengeDetail(ctx, challengeID)
	if err != nil {
		return nil, err
	}
	return &EnvState{
		UniqueCode: ch.UniqueCode,
		Status:     ch.ContainerStatus,
		Addrs:      ch.ContainerAddr,
	}, nil
}

func (c *TSecBenchClient) ExtendEnvironment(ctx context.Context, challengeID string) (*EnvState, error) {
	return c.GetEnvironment(ctx, challengeID)
}

func (c *TSecBenchClient) CloseEnvironment(ctx context.Context, challengeID string) error {
	var resp struct {
		UniqueCode string `json:"unique_code"`
		Closed     bool   `json:"closed"`
	}
	path := "/openapi/v1/challenges/close?unique_code=" + url.QueryEscape(challengeID)
	_, err := c.doJSON(ctx, http.MethodPost, path, nil, &resp)
	return err
}

func (c *TSecBenchClient) SubmitAnswer(ctx context.Context, req SubmitRequest) (*SubmitResult, error) {
	payload := map[string]string{
		"unique_code": req.UniqueCode,
		"flag":        strings.TrimSpace(req.Flag),
	}
	var resp struct {
		Correct          bool `json:"correct"`
		Awarded          int  `json:"awarded"`
		CumulativeScore  int  `json:"cumulative_score"`
		CorrectFlagCount int  `json:"correct_flag_count"`
		TotalFlagCount   int  `json:"total_flag_count"`
		MatchedFlagIndex *int `json:"matched_flag_index"`
	}
	code, err := c.doJSON(ctx, http.MethodPost, "/openapi/v1/challenges/submit", payload, &resp)
	if err != nil {
		var se *StructuredError
		if errors.As(err, &se) {
			if se.Code == "duplicate" {
				return &SubmitResult{
					Correct:    true,
					Duplicate:  true,
					Code:       "duplicate",
					Message:    se.Message,
					HTTPStatus: se.HTTPStatus,
				}, nil
			}
			return &SubmitResult{
				Correct:    false,
				Code:       se.Code,
				Message:    se.Message,
				HTTPStatus: se.HTTPStatus,
			}, err
		}
		return nil, err
	}
	completed := resp.TotalFlagCount > 0 && resp.CorrectFlagCount >= resp.TotalFlagCount
	return &SubmitResult{
		Correct:          resp.Correct,
		Awarded:          resp.Awarded,
		CumulativeScore:  resp.CumulativeScore,
		CorrectFlagCount: resp.CorrectFlagCount,
		TotalFlagCount:   resp.TotalFlagCount,
		MatchedFlagIndex: resp.MatchedFlagIndex,
		Completed:        completed,
		HTTPStatus:       code,
	}, nil
}

func (c *TSecBenchClient) GetHint(ctx context.Context, challengeID string) (string, error) {
	var resp struct {
		UniqueCode string  `json:"unique_code"`
		Hint       *string `json:"hint"`
	}
	path := "/openapi/v1/challenges/hint?unique_code=" + url.QueryEscape(challengeID)
	if _, err := c.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return "", err
	}
	if resp.Hint == nil {
		return "", nil
	}
	return *resp.Hint, nil
}

func (c *TSecBenchClient) LogNote(_ context.Context, _, _, _ string) error {
	return nil
}

func (c *TSecBenchClient) doJSON(ctx context.Context, method, path string, reqBody, out any) (int, error) {
	if c.baseURL == "" || c.token == "" {
		return 0, errors.New("TSecBench 缺少 BENCHMARK_BASE_URL 或 BENCHMARK_TOKEN")
	}
	var bodyReader io.Reader
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return 0, err
		}
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return 0, err
	}
	req.Header.Set("BENCHMARK_TOKEN", c.token)
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if out != nil && len(raw) > 0 {
			if err := json.Unmarshal(raw, out); err != nil {
				return resp.StatusCode, fmt.Errorf("解析响应失败: %w", err)
			}
		}
		return resp.StatusCode, nil
	}
	var bizErr struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(raw, &bizErr)
	msg := bizErr.Message
	if msg == "" {
		msg = strings.TrimSpace(string(raw))
	}
	code := bizErr.Code
	if code == "" && resp.StatusCode == http.StatusUnprocessableEntity {
		code = "validation_error"
	}
	return resp.StatusCode, &StructuredError{
		HTTPStatus: resp.StatusCode,
		Code:       code,
		Message:    msg,
		Retryable:  resp.StatusCode == http.StatusServiceUnavailable,
	}
}
