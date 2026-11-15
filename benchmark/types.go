package benchmark

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Provider abstracts a multi-platform benchmark / competition backend
// (TSecBench Challenges REST API, CTF2/DASCTF MCP, or Generic MCP + Skill).
type Provider interface {
	Kind() string
	WhoAmI(ctx context.Context) (*AgentProfile, error)
	ListChallenges(ctx context.Context, cfg SessionConfig) ([]ChallengeSpec, error)
	GetChallengeDetail(ctx context.Context, challengeID string) (*ChallengeSpec, error)
	DownloadAttachment(ctx context.Context, challengeID, fileID string) (filename string, data []byte, err error)
	StartEnvironment(ctx context.Context, challengeID string) (*EnvState, error)
	GetEnvironment(ctx context.Context, challengeID string) (*EnvState, error)
	ExtendEnvironment(ctx context.Context, challengeID string) (*EnvState, error)
	CloseEnvironment(ctx context.Context, challengeID string) error
	SubmitAnswer(ctx context.Context, req SubmitRequest) (*SubmitResult, error)
	GetHint(ctx context.Context, challengeID string) (string, error)
	LogNote(ctx context.Context, challengeID, kind, content string) error
}

type SessionConfig struct {
	Source             string            `json:"source,omitempty"` // auto | competition | practice
	CompetitionID      string            `json:"competition_id,omitempty"`
	StageID            string            `json:"stage_id,omitempty"`
	InviteCode         string            `json:"invite_code,omitempty"`
	CustomHeaders      map[string]string `json:"custom_headers,omitempty"`
	CTFVPNConfig       string            `json:"ctf_vpn_config,omitempty"`
	CTFVPNFilename     string            `json:"ctf_vpn_filename,omitempty"`
	SkillName          string            `json:"skill_name,omitempty"`
	SkillInstructions  string            `json:"skill_instructions,omitempty"`
	DiscoveredMCPTools []string          `json:"discovered_mcp_tools,omitempty"`
	InsecureTLS        bool              `json:"insecure_tls,omitempty"`
}

type AgentProfile struct {
	AgentID            string   `json:"agent_id,omitempty"`
	AgentName          string   `json:"agent_name,omitempty"`
	MaxEnvironments    int      `json:"max_environments"`
	ActiveEnvironments int      `json:"active_environments,omitempty"`
	CompetitionEnabled bool     `json:"competition_enabled"`
	ReadPerMin         int      `json:"read_per_min,omitempty"`
	WritePerMin        int      `json:"write_per_min,omitempty"`
	ActiveCompetitions []string `json:"active_competitions,omitempty"`
	Raw                any      `json:"raw,omitempty"`
}

type AttachmentSpec struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind,omitempty"` // static | assigned | generated
	URL  string `json:"url,omitempty"`
	Size int64  `json:"size,omitempty"`
}

type SubFlagSpec struct {
	ID    string `json:"id"`
	Title string `json:"title,omitempty"`
	Score int    `json:"score,omitempty"`
	Done  bool   `json:"done,omitempty"`
}

type ChoiceOption struct {
	Label string `json:"label"`
	Text  string `json:"text"`
}

type ChoiceMeta struct {
	QuestionType string         `json:"question_type,omitempty"` // single_choice | multiple_choice | true_false
	Options      []ChoiceOption `json:"options,omitempty"`
	AttemptsLeft int            `json:"attempts_left,omitempty"`
	Locked       bool           `json:"locked,omitempty"`
}

type ChallengeSpec struct {
	UniqueCode          string           `json:"unique_code"`
	Title               string           `json:"title"`
	Description         string           `json:"description"`
	Category            string           `json:"category"`
	Difficulty          string           `json:"difficulty"`
	Level               int              `json:"level"`
	SubmissionType      string           `json:"submission_type"` // flag | suite | choice
	TotalScore          int              `json:"total_score"`
	CumulativeScore     int              `json:"cumulative_score"`
	FlagCount           int              `json:"flag_count"`
	CorrectFlagCount    int              `json:"correct_flag_count"`
	IsCompleted         bool             `json:"is_completed"`
	ContainerStatus     string           `json:"container_status"`
	ContainerAddr       []string         `json:"container_addr"`
	HasContainer        bool             `json:"has_container"`
	Files               []AttachmentSpec `json:"files,omitempty"`
	SubFlags            []SubFlagSpec    `json:"sub_flags,omitempty"`
	Choice              *ChoiceMeta      `json:"choice,omitempty"`
	WindowState         string           `json:"window_state,omitempty"`
	PersonalFilesStatus string           `json:"personal_files_status,omitempty"`
	CompetitionID       string           `json:"competition_id,omitempty"`
	StageID             string           `json:"stage_id,omitempty"`
	PracticeGroundID    string           `json:"practice_ground_id,omitempty"`
	RawChallengeID      string           `json:"raw_challenge_id,omitempty"`
}

type EnvState struct {
	UniqueCode       string     `json:"unique_code"`
	Status           string     `json:"status"` // pending | available | stop_pending | stopped
	Addrs            []string   `json:"addrs"`
	RemainingSeconds int        `json:"remaining_seconds,omitempty"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
}

type SubmitRequest struct {
	UniqueCode string   `json:"unique_code"`
	Flag       string   `json:"flag,omitempty"`
	SubFlagID  string   `json:"sub_flag_id,omitempty"`
	Choice     []string `json:"choice,omitempty"`
}

type SubmitResult struct {
	Correct          bool   `json:"correct"`
	Duplicate        bool   `json:"duplicate,omitempty"`
	Awarded          int    `json:"awarded"`
	CumulativeScore  int    `json:"cumulative_score"`
	CorrectFlagCount int    `json:"correct_flag_count"`
	TotalFlagCount   int    `json:"total_flag_count"`
	MatchedFlagIndex *int   `json:"matched_flag_index,omitempty"`
	Completed        bool   `json:"completed"`
	Code             string `json:"code,omitempty"`
	Message          string `json:"message,omitempty"`
	RetryAfterMs     int    `json:"retry_after_ms,omitempty"`
	HTTPStatus       int    `json:"http_status,omitempty"`
}

// StructuredError captures retryable hints and rate-limit cooldowns from platforms.
type StructuredError struct {
	HTTPStatus   int    `json:"http_status"`
	Code         string `json:"code"`
	Message      string `json:"message"`
	Retryable    bool   `json:"retryable"`
	RetryAfterMs int    `json:"retry_after_ms,omitempty"`
	Hint         string `json:"hint,omitempty"`
}

func (e *StructuredError) Error() string {
	if e == nil {
		return ""
	}
	if e.Hint != "" {
		return fmt.Sprintf("%s (%d): %s [hint: %s]", e.Code, e.HTTPStatus, e.Message, e.Hint)
	}
	if e.Code != "" {
		return fmt.Sprintf("%s (%d): %s", e.Code, e.HTTPStatus, e.Message)
	}
	return fmt.Sprintf("http %d: %s", e.HTTPStatus, e.Message)
}

var (
	flagRedactRe  = regexp.MustCompile(`(?i)\b(?:flag|ctf|dasctf|tsec|hctf|qwb|xctf)\{[A-Za-z0-9_!@#$%^&*()+\-=?.,:;~|/]{3,256}\}`)
	tokenRedactRe = regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._\-]{12,}`)
)

// RedactSensitive strips potential flags and bearer tokens before emitting notes
// to external platforms such as CTF2 (`never put flags, tokens, or credentials in a note`).
func RedactSensitive(text string) string {
	out := flagRedactRe.ReplaceAllString(text, "[REDACTED_FLAG]")
	out = tokenRedactRe.ReplaceAllString(out, "${1}[REDACTED_TOKEN]")
	return strings.TrimSpace(out)
}

// InferChallengeType extracts a P3Y challenge type from code + category + description.
func InferChallengeType(code, cat, desc string) string {
	s := strings.ToLower(code + " " + cat + " " + desc)
	switch {
	case strings.Contains(s, "pwn") || strings.Contains(s, "heap") || strings.Contains(s, "rop") || strings.Contains(s, "stack"):
		return "pwn"
	case strings.Contains(s, "rev") || strings.Contains(s, "reverse") || strings.Contains(s, "apk") || strings.Contains(s, "ida"):
		return "reverse"
	case strings.Contains(s, "crypto") || strings.Contains(s, "rsa") || strings.Contains(s, "aes") || strings.Contains(s, "ecc") || strings.Contains(s, "lattice"):
		return "crypto"
	case strings.Contains(s, "misc") || strings.Contains(s, "forensics") || strings.Contains(s, "pcap") || strings.Contains(s, "stego"):
		return "misc"
	case strings.Contains(s, "web") || strings.Contains(s, "sql") || strings.Contains(s, "xss") || strings.Contains(s, "ssrf") || strings.Contains(s, "php") || strings.Contains(s, "http"):
		return "web"
	default:
		return "auto"
	}
}

func ChallengeMetaJSON(c ChallengeSpec) json.RawMessage {
	b, err := json.Marshal(struct {
		HasContainer        bool             `json:"has_container"`
		Files               []AttachmentSpec `json:"files,omitempty"`
		SubFlags            []SubFlagSpec    `json:"sub_flags,omitempty"`
		Choice              *ChoiceMeta      `json:"choice,omitempty"`
		WindowState         string           `json:"window_state,omitempty"`
		PersonalFilesStatus string           `json:"personal_files_status,omitempty"`
		CompetitionID       string           `json:"competition_id,omitempty"`
		StageID             string           `json:"stage_id,omitempty"`
		PracticeGroundID    string           `json:"practice_ground_id,omitempty"`
		RawChallengeID      string           `json:"raw_challenge_id,omitempty"`
	}{
		HasContainer:        c.HasContainer,
		Files:               c.Files,
		SubFlags:            c.SubFlags,
		Choice:              c.Choice,
		WindowState:         c.WindowState,
		PersonalFilesStatus: c.PersonalFilesStatus,
		CompetitionID:       c.CompetitionID,
		StageID:             c.StageID,
		PracticeGroundID:    c.PracticeGroundID,
		RawChallengeID:      c.RawChallengeID,
	})
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return b
}
