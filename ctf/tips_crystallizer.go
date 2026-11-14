package ctf

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"p3y/db"
	"github.com/Autumn-27/norma/llm"
)

const tipsCrystallizePrompt = `你是 CTF 与攻防系统的赛后经验提炼器（Tips Crystallizer）。请根据本次已解出题目的结构化情报（Precheck 特征、Savepoint 里程碑、Deadend 死胡同、Kit 脚本摘要），提炼 1~2 条**可跨题复用的高价值避坑卡（TipCard）**。
要求严格输出 JSON 数组，每条包含：
- "title": 简短明确的一行标题（<=50字）
- "tags": 2~5 个小写特征标签（如 ["amd64", "stack_alignment", "glibc_2_31"] 或 ["web", "ssti", "jinja2"]）
- "pitfall": 简明扼要的避坑规律（说明什么前提下会踩什么坑、正确绕过思路，<=160字）
- "pattern_code": 最关键的可复用代码片段或命令模板（1~8 行，若无可为空）
严禁输出 Markdown 代码块之外的多余废话；若情报不足，至少输出 1 条最有借鉴意义的经验。`

type crystallizedTipDraft struct {
	Title       string   `json:"title"`
	Tags        []string `json:"tags"`
	Pitfall     string   `json:"pitfall"`
	PatternCode string   `json:"pattern_code"`
}

// CrystallizeTips distills solved-task Deadends, Savepoints, Kits, and Precheck metadata
// into reusable db.TipCard rules. Idempotent per source_task_id; uses optional LLM refinement
// when prov is provided and falls back deterministically when offline.
func (s *Service) CrystallizeTips(ctx context.Context, taskID int64, prov llm.Provider) ([]db.TipCard, error) {
	if s == nil || s.DB == nil || taskID <= 0 {
		return nil, fmt.Errorf("需要任务与数据库上下文")
	}
	task, err := s.DB.GetTask(taskID)
	if err != nil || task == nil {
		return nil, fmt.Errorf("任务 #%d 不存在", taskID)
	}
	cat := strings.ToLower(strings.TrimSpace(task.ChallengeType))
	if cat == "" {
		cat = "auto"
	}

	existing, _ := s.DB.ListTips(ctx, cat, 100)
	var already []db.TipCard
	seenTitles := map[string]bool{}
	for _, c := range existing {
		if c.SourceTaskID != nil && *c.SourceTaskID == taskID {
			already = append(already, c)
		}
		seenTitles[strings.ToLower(strings.TrimSpace(c.Title))] = true
	}
	if len(already) > 0 {
		return already, nil
	}

	preRaw, _ := s.DB.TaskPrecheck(ctx, taskID)
	var pre PrecheckResult
	if len(preRaw) > 0 {
		_ = json.Unmarshal(preRaw, &pre)
	}
	items, _ := s.DB.ListBoardItems(ctx, taskID, "")
	kits, _ := s.DB.ListBoardKits(ctx, taskID)

	tags := extractTaskTipTags(cat, &pre, items)
	var drafts []crystallizedTipDraft
	if prov != nil {
		drafts = llmCrystallizeTips(ctx, prov, task.Name, cat, &pre, items, kits, tags)
	}
	if len(drafts) == 0 {
		drafts = deterministicCrystallizeTips(task.Name, cat, &pre, items, kits, tags)
	}

	var saved []db.TipCard
	srcID := taskID
	for _, d := range drafts {
		title := strings.TrimSpace(d.Title)
		if title == "" || seenTitles[strings.ToLower(title)] {
			continue
		}
		seenTitles[strings.ToLower(title)] = true
		mergedTags := append([]string{cat}, d.Tags...)
		mergedTags = append(mergedTags, tags...)
		card, cerr := s.DB.CreateTipCard(ctx, db.TipCard{
			Category:     cat,
			Tags:         mergedTags,
			Title:        title,
			Pitfall:      strings.TrimSpace(d.Pitfall),
			PatternCode:  strings.TrimSpace(d.PatternCode),
			SourceTaskID: &srcID,
		})
		if cerr == nil && card != nil {
			saved = append(saved, *card)
		}
		if len(saved) >= 2 {
			break
		}
	}
	return saved, nil
}

func extractTaskTipTags(cat string, pre *PrecheckResult, items []db.BoardItem) []string {
	var tags []string
	if cat != "" {
		tags = append(tags, cat)
	}
	if pre != nil {
		for _, bf := range pre.Files {
			if bf.Arch != "" {
				tags = append(tags, strings.ToLower(bf.Arch))
			}
			if bf.Kind != "" {
				tags = append(tags, strings.ToLower(bf.Kind))
			}
		}
		tags = append(tags, pre.Tags...)
		if len(pre.Targets) > 0 {
			tags = append(tags, "remote")
		}
	}
	for _, it := range items {
		if it.Kind == db.BoardKindDeadend {
			tags = append(tags, "deadend_learned")
			break
		}
	}
	return tags
}

func llmCrystallizeTips(ctx context.Context, prov llm.Provider, taskName, cat string, pre *PrecheckResult, items []db.BoardItem, kits []db.BoardKit, baseTags []string) []crystallizedTipDraft {
	var b strings.Builder
	fmt.Fprintf(&b, "任务名称：%s | 题型：%s | 基础标签：%s\n", taskName, cat, strings.Join(baseTags, ", "))
	if pre != nil && pre.Summary != "" {
		fmt.Fprintf(&b, "Precheck：%s\n", pre.Summary)
	}
	for _, it := range items {
		if it.Kind == db.BoardKindDeadend || it.Kind == db.BoardKindSavepoint || it.Kind == db.BoardKindFact {
			fmt.Fprintf(&b, "- [%s] %s: %s\n", it.Kind, it.Title, it.Summary)
		}
	}
	for _, k := range kits {
		fmt.Fprintf(&b, "- [kit] %s (%s): %s\n", k.Name, k.Path, k.Summary)
	}
	cctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	msg, _, _, err := prov.Complete(cctx, llm.CompletionRequest{
		System:    []string{tipsCrystallizePrompt},
		MaxTokens: 700,
		Messages:  []llm.Message{{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.TextBlock(b.String())}}},
	})
	if err != nil {
		return nil
	}
	raw := strings.TrimSpace(msg.Text())
	raw = strings.TrimPrefix(raw, "```json")
	raw = strings.TrimPrefix(raw, "```")
	raw = strings.TrimSuffix(raw, "```")
	raw = strings.TrimSpace(raw)
	var drafts []crystallizedTipDraft
	if json.Unmarshal([]byte(raw), &drafts) != nil {
		return nil
	}
	return drafts
}

func deterministicCrystallizeTips(taskName, cat string, pre *PrecheckResult, items []db.BoardItem, kits []db.BoardKit, tags []string) []crystallizedTipDraft {
	var deadends []string
	var wins []string
	for _, it := range items {
		switch it.Kind {
		case db.BoardKindDeadend:
			deadends = append(deadends, fmt.Sprintf("%s（%s）", it.Title, it.Summary))
		case db.BoardKindSavepoint:
			if it.Verified {
				wins = append(wins, fmt.Sprintf("%s：%s", it.Title, it.Summary))
			}
		}
	}
	var pattern string
	for _, k := range kits {
		if k.Path != "" {
			pattern = fmt.Sprintf("# %s: %s\n# verify: %s", k.Name, k.Summary, k.Path)
			break
		}
	}
	var pitfallParts []string
	if len(deadends) > 0 {
		pitfallParts = append(pitfallParts, "已排除陷阱："+strings.Join(deadends[:min(len(deadends), 2)], "；"))
	}
	if len(wins) > 0 {
		pitfallParts = append(pitfallParts, "有效路径："+wins[len(wins)-1])
	}
	if len(pitfallParts) == 0 && pre != nil && pre.Summary != "" {
		pitfallParts = append(pitfallParts, "复用特征模板："+pre.Summary)
	}
	if len(pitfallParts) == 0 {
		return nil
	}
	return []crystallizedTipDraft{{
		Title:       fmt.Sprintf("[%s] %s 复盘要点", strings.ToUpper(cat), truncRunes(taskName, 36)),
		Tags:        tags,
		Pitfall:     strings.Join(pitfallParts, " | "),
		PatternCode: pattern,
	}}
}

func truncRunes(s string, maxLen int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) <= maxLen {
		return string(r)
	}
	return string(r[:maxLen]) + "…"
}
