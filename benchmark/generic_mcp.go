package benchmark

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"p3y/mcphttp"
	actool "github.com/Autumn-27/norma/tool"
)

// GenericMCPClient connects to any remote HTTP MCP benchmark server (paired with
// an optional Skill.zip package). If the remote server exposes standard CTF2 tool names
// (`ctf2_agent_whoami`, etc.), lifecycle orchestration delegates seamlessly; otherwise
// it discovers safe tools and exposes them directly to the Agent runtime.
type GenericMCPClient struct {
	mcpURL      string
	token       string
	headers     map[string]string
	insecureTLS bool
	cfg         SessionConfig
	ctf2        *CTF2Client
}

func NewGenericMCPClient(mcpURL, token string, cfg SessionConfig) *GenericMCPClient {
	headers := map[string]string{}
	for k, v := range cfg.CustomHeaders {
		headers[k] = v
	}
	if strings.TrimSpace(token) != "" {
		if _, has := headers["Authorization"]; !has {
			headers["Authorization"] = "Bearer " + strings.TrimSpace(token)
		}
	}
	return &GenericMCPClient{
		mcpURL:      strings.TrimSpace(mcpURL),
		token:       strings.TrimSpace(token),
		headers:     headers,
		insecureTLS: cfg.InsecureTLS,
		cfg:         cfg,
		ctf2:        NewCTF2Client(mcpURL, token, cfg),
	}
}

func (g *GenericMCPClient) Kind() string { return "generic_mcp" }

// IsSafeBenchmarkTool strips dangerous human-only routes (writeups, tickets, admin, community)
// so automated Agents cannot accidentally trigger scope-forbidden errors or read solutions.
func IsSafeBenchmarkTool(name string) bool {
	low := strings.ToLower(name)
	for _, blocked := range []string{"writeup", "ticket", "community", "admin", "point_shop"} {
		if strings.Contains(low, blocked) {
			return false
		}
	}
	return true
}

func (g *GenericMCPClient) DiscoverSafeTools(ctx context.Context) ([]actool.CoreTool, error) {
	if g.mcpURL == "" {
		return nil, errors.New("缺少远程 MCP URL")
	}
	cl, err := mcphttp.New(ctx, "bench", g.mcpURL, g.headers, g.insecureTLS)
	if err != nil {
		return nil, err
	}
	// Caller receives wrapped CoreTool closures that share cl, or we fetch list & return wrapped tools.
	tools, err := cl.Tools(ctx)
	if err != nil {
		_ = cl.Close()
		return nil, err
	}
	out := make([]actool.CoreTool, 0, len(tools))
	for _, t := range tools {
		if IsSafeBenchmarkTool(t.Name()) {
			out = append(out, t)
		}
	}
	return out, nil
}

func (g *GenericMCPClient) WhoAmI(ctx context.Context) (*AgentProfile, error) {
	cl, err := mcphttp.New(ctx, "bench", g.mcpURL, g.headers, g.insecureTLS)
	if err != nil {
		return nil, err
	}
	defer cl.Close()
	tools, err := cl.Tools(ctx)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(tools))
	hasCTF2WhoAmI := false
	for _, t := range tools {
		if !IsSafeBenchmarkTool(t.Name()) {
			continue
		}
		names = append(names, t.Name())
		if strings.HasSuffix(t.Name(), "__ctf2_agent_whoami") || t.Name() == "ctf2_agent_whoami" {
			hasCTF2WhoAmI = true
		}
	}
	if hasCTF2WhoAmI {
		if prof, err := g.ctf2.WhoAmI(ctx); err == nil {
			prof.ActiveCompetitions = append(prof.ActiveCompetitions, names...)
			return prof, nil
		}
	}
	return &AgentProfile{
		AgentName:          "generic-mcp-agent",
		MaxEnvironments:    1,
		CompetitionEnabled: true,
		ActiveCompetitions: names,
	}, nil
}

func (g *GenericMCPClient) ListChallenges(ctx context.Context, cfg SessionConfig) ([]ChallengeSpec, error) {
	// Attempt CTF2-compatible discovery first
	if items, err := g.ctf2.ListChallenges(ctx, cfg); err == nil && len(items) > 0 {
		return items, nil
	}
	// Fallback: synthesize a single autonomous session challenge governed by Skill.md + discovered MCP tools
	rawTools, _ := json.Marshal(cfg.DiscoveredMCPTools)
	return []ChallengeSpec{{
		UniqueCode:     "mcp_autonomous_session",
		Title:          firstNonEmpty(cfg.SkillName, "MCP 自主测评赛场"),
		Description:    "通过已连接的远程 MCP 工具与 Skill 规则指引自主完成发现题目、启动靶机、求解与提交 Flag 全流程。可用工具：" + string(rawTools),
		Category:       "auto",
		Difficulty:     "auto",
		SubmissionType: "flag",
		TotalScore:     100,
		FlagCount:      1,
		HasContainer:   false,
	}}, nil
}

func (g *GenericMCPClient) GetChallengeDetail(ctx context.Context, id string) (*ChallengeSpec, error) {
	if id == "mcp_autonomous_session" {
		items, err := g.ListChallenges(ctx, g.cfg)
		if err != nil || len(items) == 0 {
			return nil, err
		}
		return &items[0], nil
	}
	return g.ctf2.GetChallengeDetail(ctx, id)
}

func (g *GenericMCPClient) DownloadAttachment(ctx context.Context, id, fileID string) (string, []byte, error) {
	return g.ctf2.DownloadAttachment(ctx, id, fileID)
}

func (g *GenericMCPClient) StartEnvironment(ctx context.Context, id string) (*EnvState, error) {
	if id == "mcp_autonomous_session" {
		return &EnvState{UniqueCode: id, Status: "available"}, nil
	}
	return g.ctf2.StartEnvironment(ctx, id)
}

func (g *GenericMCPClient) GetEnvironment(ctx context.Context, id string) (*EnvState, error) {
	if id == "mcp_autonomous_session" {
		return &EnvState{UniqueCode: id, Status: "available"}, nil
	}
	return g.ctf2.GetEnvironment(ctx, id)
}

func (g *GenericMCPClient) ExtendEnvironment(ctx context.Context, id string) (*EnvState, error) {
	if id == "mcp_autonomous_session" {
		return &EnvState{UniqueCode: id, Status: "available"}, nil
	}
	return g.ctf2.ExtendEnvironment(ctx, id)
}

func (g *GenericMCPClient) CloseEnvironment(ctx context.Context, id string) error {
	if id == "mcp_autonomous_session" {
		return nil
	}
	return g.ctf2.CloseEnvironment(ctx, id)
}

func (g *GenericMCPClient) SubmitAnswer(ctx context.Context, req SubmitRequest) (*SubmitResult, error) {
	return g.ctf2.SubmitAnswer(ctx, req)
}

func (g *GenericMCPClient) GetHint(ctx context.Context, id string) (string, error) {
	return g.ctf2.GetHint(ctx, id)
}

func (g *GenericMCPClient) LogNote(ctx context.Context, id, kind, content string) error {
	if id == "mcp_autonomous_session" {
		return nil
	}
	return g.ctf2.LogNote(ctx, id, kind, content)
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
