package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// TipCard stores a distilled post-mortem pitfall rule or reusable exploit pattern.
type TipCard struct {
	ID           int64     `json:"id"`
	Category     string    `json:"category"`
	Tags         []string  `json:"tags"`
	Title        string    `json:"title"`
	Pitfall      string    `json:"pitfall"`
	PatternCode  string    `json:"pattern_code,omitempty"`
	SourceTaskID *int64    `json:"source_task_id,omitempty"`
	HitCount     int64     `json:"hit_count"`
	CreatedAt    time.Time `json:"created_at"`
}

func normalizeTags(tags []string) []string {
	seen := make(map[string]bool, len(tags))
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		norm := strings.ToLower(strings.TrimSpace(t))
		if norm == "" || seen[norm] {
			continue
		}
		seen[norm] = true
		out = append(out, norm)
	}
	return out
}

// CreateTipCard inserts a distilled TipCard into tips_cards.
func (d *DB) CreateTipCard(ctx context.Context, card TipCard) (*TipCard, error) {
	if d == nil {
		return nil, fmt.Errorf("db is nil")
	}
	card.Title = strings.TrimSpace(card.Title)
	if card.Title == "" {
		return nil, fmt.Errorf("tip title required")
	}
	cat := strings.ToLower(strings.TrimSpace(card.Category))
	if cat == "" {
		cat = "auto"
	}
	tags := normalizeTags(card.Tags)
	tagsRaw, _ := json.Marshal(tags)
	var srcTask sql.NullInt64
	if card.SourceTaskID != nil && *card.SourceTaskID > 0 {
		srcTask = sql.NullInt64{Int64: *card.SourceTaskID, Valid: true}
	}
	var out TipCard
	var outTagsRaw string
	var outSrc sql.NullInt64
	err := d.QueryRowContext(ctx, `
		INSERT INTO tips_cards (category, tags_json, title, pitfall, pattern_code, source_task_id, hit_count)
		VALUES ($1, $2::jsonb, $3, $4, $5, $6, $7)
		RETURNING id, category, tags_json::text, title, pitfall, pattern_code, source_task_id, hit_count, created_at
	`, cat, string(tagsRaw), card.Title, strings.TrimSpace(card.Pitfall), strings.TrimSpace(card.PatternCode), srcTask, card.HitCount).
		Scan(&out.ID, &out.Category, &outTagsRaw, &out.Title, &out.Pitfall, &out.PatternCode, &outSrc, &out.HitCount, &out.CreatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(outTagsRaw), &out.Tags)
	if outSrc.Valid {
		v := outSrc.Int64
		out.SourceTaskID = &v
	}
	return &out, nil
}

// ListTips lists tip cards filtered optionally by category.
func (d *DB) ListTips(ctx context.Context, category string, limit int) ([]TipCard, error) {
	if d == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	cat := strings.ToLower(strings.TrimSpace(category))
	query := `
		SELECT id, category, tags_json::text, title, pitfall, pattern_code, source_task_id, hit_count, created_at
		FROM tips_cards`
	var args []any
	if cat != "" && cat != "all" && cat != "auto" {
		query += ` WHERE category IN ($1, 'auto')`
		args = append(args, cat)
		query += ` ORDER BY hit_count DESC, id DESC LIMIT $2`
		args = append(args, limit)
	} else {
		query += ` ORDER BY hit_count DESC, id DESC LIMIT $1`
		args = append(args, limit)
	}
	rows, err := d.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TipCard
	for rows.Next() {
		var c TipCard
		var tagsRaw string
		var src sql.NullInt64
		if err := rows.Scan(&c.ID, &c.Category, &tagsRaw, &c.Title, &c.Pitfall, &c.PatternCode, &src, &c.HitCount, &c.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(tagsRaw), &c.Tags)
		if src.Valid {
			v := src.Int64
			c.SourceTaskID = &v
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SearchTips retrieves up to limit relevant tip cards scored by category match + tag overlap + hit_count.
func (d *DB) SearchTips(ctx context.Context, category string, tags []string, limit int) ([]TipCard, error) {
	if d == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 20 {
		limit = 5
	}
	all, err := d.ListTips(ctx, category, 200)
	if err != nil || len(all) == 0 {
		return all, err
	}
	wantTags := normalizeTags(tags)
	wantCat := strings.ToLower(strings.TrimSpace(category))

	type scored struct {
		card  TipCard
		score int
	}
	ranked := make([]scored, 0, len(all))
	for _, c := range all {
		score := 0
		if wantCat != "" && wantCat != "auto" && c.Category == wantCat {
			score += 3
		}
		hay := strings.ToLower(c.Title + " " + c.Pitfall)
		cardTagSet := make(map[string]bool, len(c.Tags))
		for _, t := range c.Tags {
			cardTagSet[strings.ToLower(t)] = true
		}
		for _, wt := range wantTags {
			if cardTagSet[wt] {
				score += 5
			} else if strings.Contains(hay, wt) {
				score += 2
			}
		}
		if len(wantTags) == 0 || score > 0 {
			ranked = append(ranked, scored{card: c, score: score})
		}
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		if ranked[i].score != ranked[j].score {
			return ranked[i].score > ranked[j].score
		}
		if ranked[i].card.HitCount != ranked[j].card.HitCount {
			return ranked[i].card.HitCount > ranked[j].card.HitCount
		}
		return ranked[i].card.ID > ranked[j].card.ID
	})
	if len(ranked) > limit {
		ranked = ranked[:limit]
	}
	out := make([]TipCard, len(ranked))
	for i, r := range ranked {
		out[i] = r.card
	}
	return out, nil
}

// IncrementTipHit bumps hit_count when a TipCard is recalled or cited.
func (d *DB) IncrementTipHit(ctx context.Context, id int64) error {
	if d == nil || id <= 0 {
		return nil
	}
	_, err := d.ExecContext(ctx, `UPDATE tips_cards SET hit_count = hit_count + 1 WHERE id=$1`, id)
	return err
}

// DeleteTipCard removes a tip card by ID.
func (d *DB) DeleteTipCard(ctx context.Context, id int64) error {
	if d == nil || id <= 0 {
		return fmt.Errorf("invalid tip id")
	}
	res, err := d.ExecContext(ctx, `DELETE FROM tips_cards WHERE id=$1`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// SeedDefaultTips idempotently seeds starter CTF pitfall cards when tips_cards is empty.
func (d *DB) SeedDefaultTips(ctx context.Context) error {
	if d == nil {
		return nil
	}
	var cnt int
	if err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM tips_cards`).Scan(&cnt); err != nil {
		return err
	}
	if cnt > 0 {
		return nil
	}
	defaults := []TipCard{
		{
			Category: "pwn",
			Tags:     []string{"elf", "amd64", "libc", "stack_alignment", "pwn"},
			Title:    "amd64 Ubuntu libc system(\"/bin/sh\") 栈 16 字节对齐崩溃",
			Pitfall:  "glibc >= 2.27 amd64 下调用 system() 若 RSP 未按 16 字节对齐（movaps xmm 触发 SIGSEGV），可在 payload 中加一个单纯的 ret gadget。",
			PatternCode: "ret = next(elf.search(asm('ret')))\npayload = flat({offset: [ret, pop_rdi, binsh, libc.sym['system']]})",
		},
		{
			Category: "pwn",
			Tags:     []string{"elf", "pwn", "libc_provided", "canary", "stripped"},
			Title:    "先交互套件与本地 patchelf 验证，再切换远程打靶",
			Pitfall:  "不要在未确认栈/堆偏移与 libc 版本匹配时盲打远程；先通过 ctf_pwn_triage 生成 *_patched 并在本地 verify 通过，把 interact.py 存成 Kit 后复用。",
			PatternCode: "p = remote(host, port) if args.REMOTE else process('./chall_patched')",
		},
		{
			Category: "reverse",
			Tags:     []string{"elf", "pe", "stripped", "reverse", "ghidra"},
			Title:    "stripped 二进制优先用 ctf_decompile（Ghidra 缓存）配合 Z3 约束求解",
			Pitfall:  "用 objdump 通篇看 stripped 二进制会消耗大量上下文；优先调用 ctf_decompile 导入缓存，逐 byte 加密校验直接交给 z3.Solver。",
			PatternCode: "s = Solver()\nx = [BitVec(f'b{i}', 8) for i in range(n)]\nassert s.check() == sat",
		},
		{
			Category: "web",
			Tags:     []string{"web", "http", "ssti", "php", "python", "sql"},
			Title:    "Web 探测留痕与 WAF 字符集差分",
			Pitfall:  "盲目目录扫描噪音大且易触发限流；优先用 http_send/ctf_http 测单点回显并利用 traffic_search 回看响应细节，遇到过滤时先验证最小可用字符集。",
		},
		{
			Category: "misc",
			Tags:     []string{"pcap", "pcapng", "zip", "zip_encrypted", "misc"},
			Title:    "流量包与伪加密 Zip 的 0 盲猜初筛",
			Pitfall:  "PCAP/PCAPNG 先跑 ctf_pcap_analyze(mode=summary/http/export/search)；Zip 提示要密码但无提示时先检查中央目录通用位标志（伪加密 09 00）。",
		},
	}
	for _, c := range defaults {
		if _, err := d.CreateTipCard(ctx, c); err != nil {
			return err
		}
	}
	return nil
}
