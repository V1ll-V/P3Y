package ad

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"p3y/ctf"
	"p3y/db"
	"p3y/traffic"
)

// Service orchestrates Stage-5 Autonomous Attack-Defense engines:
// 0-LLM periodic Repeater, inbound Catcher mirror, Red-Blue Patcher co-verifier,
// and Lead priority/stop-loss/salvage recommendations.
type Service struct {
	DB      *db.DB
	CTF     *ctf.Service
	Traffic *traffic.Traffic
	HTTP    *http.Client
}

// LeadRecommendation captures one actionable recommendation computed by the Lead engine.
type LeadRecommendation struct {
	Priority string `json:"priority"` // high | medium | low
	Kind     string `json:"kind"`     // easy_first | stop_loss | salvage_payload | verify_patch
	Target   string `json:"target,omitempty"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
}

// ADOverview aggregates live Attack-Defense state for a task.
type ADOverview struct {
	Weapons         []db.ADWeapon        `json:"weapons"`
	Events          []db.ADEvent         `json:"events"`
	Recommendations []LeadRecommendation `json:"recommendations"`
}

// Overview builds a live Lead/Repeater/Catcher/Patcher snapshot for taskID.
func (s *Service) Overview(ctx context.Context, taskID int64) (*ADOverview, error) {
	if s == nil || s.DB == nil || taskID <= 0 {
		return nil, fmt.Errorf("需要任务与数据库上下文")
	}
	weapons, err := s.DB.ListADWeapons(ctx, taskID)
	if err != nil {
		return nil, err
	}
	events, err := s.DB.ListADEvents(ctx, taskID, 60)
	if err != nil {
		return nil, err
	}
	if weapons == nil {
		weapons = []db.ADWeapon{}
	}
	if events == nil {
		events = []db.ADEvent{}
	}
	recs := buildLeadRecommendations(weapons, events)
	return &ADOverview{
		Weapons:         weapons,
		Events:          events,
		Recommendations: recs,
	}, nil
}

func buildLeadRecommendations(weapons []db.ADWeapon, events []db.ADEvent) []LeadRecommendation {
	var recs []LeadRecommendation
	for _, w := range weapons {
		switch {
		case w.Status == db.ADWeaponBlocked || w.ConsecutiveFails >= 3:
			recs = append(recs, LeadRecommendation{
				Priority: "high",
				Kind:     "stop_loss",
				Target:   w.TargetService,
				Title:    fmt.Sprintf("止损检修武器 #%d（%s）", w.ID, firstNonEmpty(w.TargetService, w.ScriptPath)),
				Detail:   fmt.Sprintf("连续失败 %d 次（末次报错：%s），已进入 blocked，建议调度 Breaker 排查目标补丁或更新利用链。", w.ConsecutiveFails, firstNonEmpty(w.LastError, "未获 Flag")),
			})
		case w.Status == db.ADWeaponActive && w.SuccessCount == 0 && w.LastRunAt == nil:
			recs = append(recs, LeadRecommendation{
				Priority: "medium",
				Kind:     "easy_first",
				Target:   w.TargetService,
				Title:    fmt.Sprintf("待首轮打靶：%s", firstNonEmpty(w.TargetService, w.ScriptPath)),
				Detail:   fmt.Sprintf("武器 #%d 尚未执行过打靶（目标 %d 个），建议立刻触发 Repeater 抢分。", w.ID, len(w.Targets)),
			})
		}
	}

	var recentAlert *db.ADEvent
	var hasRecentPatch bool
	for i := range events {
		ev := &events[i]
		if ev.Role == "catcher" && ev.Kind == "alert" && recentAlert == nil {
			recentAlert = ev
		}
		if ev.Role == "patcher" && ev.Kind == "patch_test" {
			hasRecentPatch = true
		}
	}
	if recentAlert != nil {
		recs = append(recs, LeadRecommendation{
			Priority: "high",
			Kind:     "salvage_payload",
			Target:   recentAlert.Target,
			Title:    "Catcher 捕获入站攻击载荷（可打捞反打 + 加固）",
			Detail:   recentAlert.Summary,
		})
		if !hasRecentPatch {
			recs = append(recs, LeadRecommendation{
				Priority: "high",
				Kind:     "verify_patch",
				Target:   recentAlert.Target,
				Title:    "建议立即启动 Patcher 红蓝对撞验证",
				Detail:   "已发现入站异常攻击流量但尚无补丁测试记录，建议使用 Patcher 以“SLA 正常 + 阻断攻击”双向验证防御补丁。",
			})
		}
	}
	if recs == nil {
		recs = []LeadRecommendation{}
	}
	return recs
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func (s *Service) httpClient() *http.Client {
	if s != nil && s.HTTP != nil {
		return s.HTTP
	}
	return &http.Client{Timeout: 8 * time.Second}
}
