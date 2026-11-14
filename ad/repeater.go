package ad

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"p3y/ctf"
	"p3y/db"
)

// RepeaterRunResult summarizes one deterministic 0-LLM batch attack sweep.
type RepeaterRunResult struct {
	WeaponsRun   int      `json:"weapons_run"`
	TargetsHit   int      `json:"targets_hit"`
	TargetsMiss  int      `json:"targets_miss"`
	FlagsFound   []string `json:"flags_found"`
	BlockedCount int      `json:"blocked_count"`
}

// RunRepeater runs active AD weapons for taskID against their configured targets with 0 LLM tokens.
// When weaponID > 0, only that weapon runs (even if paused, when force=true).
func (s *Service) RunRepeater(ctx context.Context, taskID, weaponID int64, force bool) (*RepeaterRunResult, error) {
	if s == nil || s.DB == nil || s.CTF == nil || taskID <= 0 {
		return nil, fmt.Errorf("需要任务、数据库与沙箱上下文")
	}
	weapons, err := s.DB.ListADWeapons(ctx, taskID)
	if err != nil {
		return nil, err
	}
	out := &RepeaterRunResult{FlagsFound: []string{}}
	now := time.Now()
	for _, w := range weapons {
		if weaponID > 0 && w.ID != weaponID {
			continue
		}
		if w.Status != db.ADWeaponActive && !(force && weaponID == w.ID) {
			continue
		}
		if !force && w.LastRunAt != nil && now.Sub(*w.LastRunAt) < time.Duration(max(w.IntervalSec, 10))*time.Second {
			continue
		}
		out.WeaponsRun++
		targets := w.Targets
		if len(targets) == 0 {
			targets = []string{""}
		}

		var customRe *regexp.Regexp
		if strings.TrimSpace(w.FlagRegex) != "" {
			customRe, _ = regexp.Compile(strings.TrimSpace(w.FlagRegex))
		}

		hits, misses := 0, 0
		var lastFlag, lastErr string
		for _, target := range targets {
			cmd := buildWeaponCommand(w.CheckCmd, target)
			execRes, execErr := s.CTF.ExecuteRaw(ctx, taskID, 0, cmd, 30)
			if execErr != nil {
				misses++
				lastErr = execErr.Error()
				_, _ = s.DB.AddADEvent(ctx, db.ADEvent{
					TaskID:   taskID,
					WeaponID: &w.ID,
					Role:     "repeater",
					Kind:     "round_miss",
					Target:   target,
					Summary:  fmt.Sprintf("打靶异常：%v", execErr),
				})
				continue
			}

			combined := execRes.StdoutExcerpt + "\n" + execRes.StderrExcerpt
			var flags []string
			if customRe != nil {
				flags = append(flags, customRe.FindAllString(combined, 4)...)
			}
			if len(flags) == 0 {
				flags = ctf.ExtractFlags(combined, 4)
			}

			if len(flags) > 0 && execRes.ExitCode == 0 {
				hits++
				flag := flags[0]
				lastFlag = flag
				out.FlagsFound = append(out.FlagsFound, flag)
				submitStatus := "captured"
				if strings.TrimSpace(w.SubmitURL) != "" {
					if serr := s.submitADFlag(ctx, w.SubmitURL, w.SubmitToken, w.TargetService, target, flag); serr != nil {
						submitStatus = "submit_error: " + serr.Error()
					} else {
						submitStatus = "submitted"
					}
				}
				detail, _ := json.Marshal(map[string]any{
					"flag":         flag,
					"execution_id": execRes.ID,
					"status":       submitStatus,
				})
				_, _ = s.DB.AddADEvent(ctx, db.ADEvent{
					TaskID:   taskID,
					WeaponID: &w.ID,
					Role:     "repeater",
					Kind:     "round_hit",
					Target:   target,
					Summary:  fmt.Sprintf("命中目标 %s，获取 Flag `%s`（%s）", firstNonEmpty(target, w.TargetService), flag, submitStatus),
					Detail:   detail,
				})
			} else {
				misses++
				lastErr = firstNonEmpty(execRes.Error, fmt.Sprintf("exit=%d, 未匹配到 Flag", execRes.ExitCode))
				_, _ = s.DB.AddADEvent(ctx, db.ADEvent{
					TaskID:   taskID,
					WeaponID: &w.ID,
					Role:     "repeater",
					Kind:     "round_miss",
					Target:   target,
					Summary:  fmt.Sprintf("打靶未得分（%s）：%s", firstNonEmpty(target, w.TargetService), lastErr),
				})
			}
		}

		out.TargetsHit += hits
		out.TargetsMiss += misses
		updated, rerr := s.DB.RecordADWeaponRun(ctx, taskID, w.ID, hits, misses, lastFlag, lastErr)
		if rerr == nil && updated != nil && updated.Status == db.ADWeaponBlocked && w.Status != db.ADWeaponBlocked {
			out.BlockedCount++
			_, _ = s.DB.AddADEvent(ctx, db.ADEvent{
				TaskID:   taskID,
				WeaponID: &w.ID,
				Role:     "lead",
				Kind:     "lead_decision",
				Target:   w.TargetService,
				Summary:  fmt.Sprintf("武器 #%d 连续失败 %d 次触发自动止损（blocked），等待 Breaker 修复或重新激活", w.ID, updated.ConsecutiveFails),
			})
		}
	}
	return out, nil
}

// TickDueWeapons checks all active AD weapons across open tasks and runs any whose interval elapsed.
func (s *Service) TickDueWeapons(ctx context.Context) error {
	if s == nil || s.DB == nil || s.CTF == nil {
		return nil
	}
	weapons, err := s.DB.ListADWeapons(ctx, 0)
	if err != nil || len(weapons) == 0 {
		return err
	}
	seenTasks := map[int64]bool{}
	now := time.Now()
	for _, w := range weapons {
		if seenTasks[w.TaskID] {
			continue
		}
		if w.LastRunAt == nil || now.Sub(*w.LastRunAt) >= time.Duration(max(w.IntervalSec, 10))*time.Second {
			seenTasks[w.TaskID] = true
			if _, runErr := s.RunRepeater(ctx, w.TaskID, 0, false); runErr != nil {
				// Best-effort per task; keep scheduler running cleanly.
				continue
			}
		}
	}
	return nil
}

func buildWeaponCommand(template, target string) string {
	t := strings.TrimSpace(target)
	if strings.Contains(template, "{TARGET}") {
		return strings.ReplaceAll(template, "{TARGET}", quoteArg(t))
	}
	if t == "" {
		return template
	}
	return template + " " + quoteArg(t)
}

func quoteArg(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

func (s *Service) submitADFlag(ctx context.Context, submitURL, token, serviceName, target, flag string) error {
	body, _ := json.Marshal(map[string]string{
		"flag":    flag,
		"target":  target,
		"service": serviceName,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, submitURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Team-Token", token)
	}
	resp, err := s.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	return nil
}
