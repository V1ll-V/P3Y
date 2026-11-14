package ad

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"p3y/db"
	"p3y/traffic"
)

// CatcherSample represents an explicit HTTP/raw payload sample fed into Catcher.
type CatcherSample struct {
	Target  string `json:"target"`
	Request string `json:"request"`
	Source  string `json:"source,omitempty"`
}

// CatcherFinding describes a matched inbound attack signature.
type CatcherFinding struct {
	Signature string `json:"signature"`
	Category  string `json:"category"`
	Target    string `json:"target"`
	Excerpt   string `json:"excerpt"`
}

// CatcherScanResult reports alerts discovered during a Catcher scan pass.
type CatcherScanResult struct {
	Scanned  int              `json:"scanned"`
	Findings []CatcherFinding `json:"findings"`
}

var catcherPatterns = []struct {
	Category string
	Name     string
	Re       *regexp.Regexp
}{
	{"cmdi", "shell_command_injection", regexp.MustCompile(`(?i)(;\s*(cat|ls|id|whoami|nc|bash|sh|curl|wget)\b|\$\([^)]+\)|` + "`" + `[^` + "`" + `]+` + "`" + `|/bin/(ba)?sh)`)},
	{"sqli", "sql_injection", regexp.MustCompile(`(?i)(\bunion\s+(all\s+)?select\b|'\s*or\s+1\s*=\s*1|\bsleep\s*\(\s*\d|\bbenchmark\s*\()`)},
	{"ssti", "template_injection", regexp.MustCompile(`(\{\{[^}]{1,120}\}\}|\$\{[^}]{1,120}\}|__class__|__mro__|__subclasses__)`)},
	{"lfi", "path_traversal_flag_read", regexp.MustCompile(`(?i)(\.\./\.\./|/flag\b|/etc/passwd)`)},
	{"deser", "php_java_deserialization", regexp.MustCompile(`(O:\d+:"[A-Za-z0-9_\\]+":\d+:\{|rO0AB[A-Za-z0-9+/=]+)`)},
	{"bin", "format_string_or_nopsled", regexp.MustCompile(`(%[0-9]+\$[xpsn]|(%n){2,}|\\x90\\x90\\x90)`)},
}

// ScanCatcher analyzes explicit Catcher samples (or recent MITM traffic rows when samples is empty)
// for enemy exploit payloads, persists Catcher alerts into ad_events & Board facts, and exposes
// captured payloads for counter-replay (Salvage) and Patcher defense.
func (s *Service) ScanCatcher(ctx context.Context, taskID int64, samples []CatcherSample, recordBoard bool) (*CatcherScanResult, error) {
	if s == nil || s.DB == nil || taskID <= 0 {
		return nil, fmt.Errorf("需要任务与数据库上下文")
	}
	if len(samples) == 0 && s.Traffic != nil {
		rows, _, err := s.Traffic.Page(traffic.PageQuery{}, 0, 30)
		if err == nil {
			for _, r := range rows {
				reqText, _, gerr := s.Traffic.Get(r.ID)
				if gerr != nil || strings.TrimSpace(reqText) == "" {
					continue
				}
				samples = append(samples, CatcherSample{
					Target:  r.Host + r.Path,
					Request: reqText,
					Source:  "traffic:" + r.ID,
				})
			}
		}
	}

	res := &CatcherScanResult{
		Scanned:  len(samples),
		Findings: []CatcherFinding{},
	}
	seen := map[string]bool{}
	for _, sample := range samples {
		text := strings.TrimSpace(sample.Request)
		if text == "" {
			continue
		}
		for _, pat := range catcherPatterns {
			loc := pat.Re.FindString(text)
			if loc == "" {
				continue
			}
			sigKey := pat.Name + "|" + sample.Target + "|" + loc
			if seen[sigKey] {
				continue
			}
			seen[sigKey] = true
			excerpt := loc
			if len(excerpt) > 180 {
				excerpt = excerpt[:180]
			}
			f := CatcherFinding{
				Signature: pat.Name,
				Category:  pat.Category,
				Target:    firstNonEmpty(sample.Target, "unknown"),
				Excerpt:   excerpt,
			}
			res.Findings = append(res.Findings, f)
			detail, _ := json.Marshal(map[string]any{
				"category":  f.Category,
				"signature": f.Signature,
				"excerpt":   f.Excerpt,
				"source":    sample.Source,
				"sample":    truncateStr(text, 600),
			})
			_, _ = s.DB.AddADEvent(ctx, db.ADEvent{
				TaskID:  taskID,
				Role:    "catcher",
				Kind:    "alert",
				Target:  f.Target,
				Summary: fmt.Sprintf("检测到疑似 %s 攻击特征 (%s)：%s", f.Category, f.Signature, f.Excerpt),
				Detail:  detail,
			})
			if recordBoard {
				_, _ = s.DB.AddBoardItem(ctx, db.BoardItem{
					TaskID:   taskID,
					Kind:     db.BoardKindFact,
					Title:    fmt.Sprintf("[Catcher 入站告警] %s (%s)", f.Signature, f.Target),
					Summary:  fmt.Sprintf("捕获入站 %s 攻击样本：%s（可评估反打打捞与补丁对撞）", f.Category, f.Excerpt),
					Detail:   truncateStr(text, 2000),
					Verified: true,
				})
			}
		}
	}
	return res, nil
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
