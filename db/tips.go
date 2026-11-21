package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
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
	SolveCount   int64     `json:"solve_count"`
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
		INSERT INTO tips_cards (category, tags_json, title, pitfall, pattern_code, source_task_id, hit_count, solve_count)
		VALUES ($1, $2::jsonb, $3, $4, $5, $6, $7, $8)
		RETURNING id, category, tags_json::text, title, pitfall, pattern_code, source_task_id, hit_count, solve_count, created_at
	`, cat, string(tagsRaw), card.Title, strings.TrimSpace(card.Pitfall), strings.TrimSpace(card.PatternCode), srcTask, card.HitCount, card.SolveCount).
		Scan(&out.ID, &out.Category, &outTagsRaw, &out.Title, &out.Pitfall, &out.PatternCode, &outSrc, &out.HitCount, &out.SolveCount, &out.CreatedAt)
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
		SELECT id, category, tags_json::text, title, pitfall, pattern_code, source_task_id, hit_count, solve_count, created_at
		FROM tips_cards`
	var args []any
	if cat != "" && cat != "all" && cat != "auto" {
		query += ` WHERE category IN ($1, 'auto')`
		args = append(args, cat)
		query += ` ORDER BY solve_count DESC, hit_count DESC, id DESC LIMIT $2`
		args = append(args, limit)
	} else {
		query += ` ORDER BY solve_count DESC, hit_count DESC, id DESC LIMIT $1`
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
		if err := rows.Scan(&c.ID, &c.Category, &tagsRaw, &c.Title, &c.Pitfall, &c.PatternCode, &src, &c.HitCount, &c.SolveCount, &c.CreatedAt); err != nil {
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

func isCoarseCategoryTag(tag string) bool {
	switch strings.ToLower(strings.TrimSpace(tag)) {
	case "pwn", "reverse", "web", "crypto", "misc", "ad", "auto", "all":
		return true
	default:
		return false
	}
}

// SearchTips retrieves up to limit relevant tip cards scored by category/tag relevance plus Bayesian solve rate.
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
		score float64
	}
	ranked := make([]scored, 0, len(all))
	for _, c := range all {
		catBonus := 0.0
		if wantCat != "" && wantCat != "auto" && c.Category == wantCat {
			catBonus = 3.0
		}
		hay := strings.ToLower(c.Title + " " + c.Pitfall)
		cardTagSet := make(map[string]bool, len(c.Tags))
		for _, t := range c.Tags {
			cardTagSet[strings.ToLower(t)] = true
		}
		tagMatchScore := 0.0
		for _, wt := range wantTags {
			if isCoarseCategoryTag(wt) {
				continue
			}
			if cardTagSet[wt] {
				tagMatchScore += 5.0
			} else if strings.Contains(hay, wt) {
				tagMatchScore += 2.0
			}
		}
		if len(wantTags) > 0 && tagMatchScore == 0 {
			continue
		}
		relScore := catBonus + tagMatchScore
		// Bayesian smoothed win-rate prior plus self-cleaning penalty for cards recalled repeatedly without solving.
		winRate := float64(c.SolveCount+1) / float64(c.HitCount+3)
		score := relScore + winRate*4.0
		if c.HitCount >= 5 && c.SolveCount == 0 {
			score -= 6.0
		}
		ranked = append(ranked, scored{card: c, score: score})
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		if ranked[i].score != ranked[j].score {
			return ranked[i].score > ranked[j].score
		}
		if ranked[i].card.SolveCount != ranked[j].card.SolveCount {
			return ranked[i].card.SolveCount > ranked[j].card.SolveCount
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

// RecordTaskTipHit records at most one hit per (taskID, tipID) and bumps hit_count once per task.
func (d *DB) RecordTaskTipHit(ctx context.Context, taskID, tipID int64) error {
	if d == nil || tipID <= 0 {
		return nil
	}
	if taskID <= 0 {
		return d.IncrementTipHit(ctx, tipID)
	}
	_, err := d.ExecContext(ctx, `
		WITH ins AS (
			INSERT INTO task_tip_hits (task_id, tip_id)
			VALUES ($1, $2)
			ON CONFLICT (task_id, tip_id) DO NOTHING
			RETURNING tip_id
		)
		UPDATE tips_cards
		SET hit_count = hit_count + 1
		WHERE id IN (SELECT tip_id FROM ins)
	`, taskID, tipID)
	return err
}

// MarkTaskTipsSolved credits solve_count once per recalled tip card when taskID solves.
func (d *DB) MarkTaskTipsSolved(ctx context.Context, taskID int64) error {
	if d == nil || taskID <= 0 {
		return nil
	}
	_, err := d.ExecContext(ctx, `
		WITH newly_solved AS (
			UPDATE task_tip_hits
			SET solved = TRUE
			WHERE task_id = $1 AND solved = FALSE
			RETURNING tip_id
		)
		UPDATE tips_cards
		SET solve_count = solve_count + 1
		WHERE id IN (SELECT tip_id FROM newly_solved)
	`, taskID)
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

// SeedDefaultTips idempotently seeds starter CTF pitfall cards by title so newly added
// built-in cards are also backfilled into existing deployments without duplicating.
func (d *DB) SeedDefaultTips(ctx context.Context) error {
	if d == nil {
		return nil
	}
	if os.Getenv("P3Y_HOSTED_MODE") == "1" || os.Getenv("P3Y_SKIP_BUILTIN_TIPS") == "1" {
		return nil
	}
	existing := map[string]bool{}
	rows, err := d.QueryContext(ctx, `SELECT LOWER(TRIM(title)) FROM tips_cards`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var title string
		if rows.Scan(&title) == nil && title != "" {
			existing[title] = true
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	defaults := []TipCard{
		{
			Category:    "pwn",
			Tags:        []string{"elf", "amd64", "libc", "stack_alignment", "pwn"},
			Title:       "amd64 Ubuntu libc system(\"/bin/sh\") 栈 16 字节对齐崩溃",
			Pitfall:     "glibc >= 2.27 amd64 下调用 system() 若 RSP 未按 16 字节对齐（movaps xmm 触发 SIGSEGV），可在 payload 中加一个单纯的 ret gadget。",
			PatternCode: "ret = next(elf.search(asm('ret')))\npayload = flat({offset: [ret, pop_rdi, binsh, libc.sym['system']]})",
		},
		{
			Category:    "pwn",
			Tags:        []string{"elf", "pwn", "libc_provided", "canary", "stripped"},
			Title:       "先交互套件与本地 patchelf 验证，再切换远程打靶",
			Pitfall:     "不要在未确认栈/堆偏移与 libc 版本匹配时盲打远程；先通过 ctf_pwn_triage 生成 *_patched 并在本地 verify 通过，把 interact.py 存成 Kit 后复用。",
			PatternCode: "p = remote(host, port) if args.REMOTE else process('./chall_patched')",
		},
		{
			Category:    "reverse",
			Tags:        []string{"elf", "pe", "stripped", "reverse", "ghidra"},
			Title:       "stripped 二进制优先用 ctf_decompile（Ghidra 缓存）配合 Z3 约束求解",
			Pitfall:     "用 objdump 通篇看 stripped 二进制会消耗大量上下文；优先调用 ctf_decompile 导入缓存，逐 byte 加密校验直接交给 z3.Solver。",
			PatternCode: "s = Solver()\nx = [BitVec(f'b{i}', 8) for i in range(n)]\nassert s.check() == sat",
		},
		{
			Category: "web",
			Tags:     []string{"web", "http", "ssti", "php", "python", "sql"},
			Title:    "Web 探测留痕与 WAF 字符集差分",
			Pitfall:  "盲目目录扫描噪音大且易触发限流；优先用 ctf_http 测单点回显并利用 traffic_search 回看响应细节，遇到过滤时先验证最小可用字符集。",
		},
		{
			Category: "misc",
			Tags:     []string{"pcap", "pcapng", "zip", "zip_encrypted", "misc"},
			Title:    "流量包与伪加密 Zip 的 0 盲猜初筛",
			Pitfall:  "PCAP/PCAPNG 先跑 ctf_pcap_analyze(mode=summary/http/export/search)；Zip 提示要密码但无提示时先检查中央目录通用位标志（伪加密 09 00）。",
		},
		{
			Category:    "web",
			Tags:        []string{"web", "nextjs", "middleware", "ssrf"},
			Title:       "Next.js Middleware 鉴权绕过与 SSRF 内部 Header 窃取",
			Pitfall:     "测 x-middleware-subrequest 5 段重复绕过；SSRF 遇到内部服务报 401 invalid token 时，在容器 0.0.0.0 起监听并让 SSRF 访问本机 VPN tun0 IP 抓包提取客户端自带的认证头。",
			PatternCode: "headers = {'x-middleware-subrequest': 'middleware:middleware:middleware:middleware:middleware'}",
		},
		{
			Category:    "web",
			Tags:        []string{"web", "react", "nodejs", "rsc", "nginx"},
			Title:       "React Flight (RSC) 反序列化 RCE 与前置 Nginx X-Accel-Redirect",
			Pitfall:     "Flight 协议反序列化拿到 app 容器 RCE 后若本地无 flag，检查前置反向代理（Nginx），可通过 hook ServerResponse.prototype.writeHead 注入 X-Accel-Redirect 读取网关容器内受保护路径或内部 upstream。",
			PatternCode: "res.setHeader('X-Accel-Redirect', '/internal_flag')",
		},
		{
			Category:    "web",
			Tags:        []string{"web", "php", "session", "unserialize", "lfi"},
			Title:       "PHP php_serialize 与 php 处理器不一致 (|) Session 反序列化 + Filter Chain",
			Pitfall:     "当某页面用 php_serialize 写入可控字符串、另一页面用 php 处理器解析同一 Session ID 时，注入 |O:... 触发对象注入；多实例环境务必复用单一 Keep-Alive 连接；配合 php_filter_chain_generator 将无回显 include 转为 RCE。",
			PatternCode: "php_filter_chain_generator --chain '<?php system($_GET[0]); ?>'",
		},
		{
			Category:    "web",
			Tags:        []string{"web", "sql", "postgres", "waf", "dblink"},
			Title:       "PostgreSQL 宽字节 (%bf%27) WAF 失步逃逸与 dblink 内网跨库",
			Pitfall:     "当 WAF 按 UTF-8/文本检查而底层驱动按多字节处理时，测试 %bf%27 / %bf%5c 吃掉转义或使 WAF 失步放行 --（%2d%2d）；拿到 app-db 堆叠/UNION 后，先完整读完提示表（用 substr 防截断），再用 pg_read_file 读凭据配合 dblink 访问隔离网段数据库。",
			PatternCode: "SELECT dblink_connect('conn', 'host=... dbname=... user=... password=...');",
		},
		{
			Category:    "web",
			Tags:        []string{"web", "python", "ssti", "bottle", "jinja2"},
			Title:       "Python / Bottle 模板受限沙箱与无 / 只读文件原语",
			Pitfall:     "当模板注入对 {{7*7}} 无回显且过滤路径分隔符 / 时，构造 chr(47)+'flag' 并利用标准库只读文件原语（如 __import__('linecache').getline(chr(47)+'flag',1) 或 open(chr(47)+'flag').read()）直接触发读取求值。",
			PatternCode: "{{__import__('linecache').getline(chr(47)+'flag',1)}}",
		},
		{
			Category:    "web",
			Tags:        []string{"web", "race_condition", "pow", "captcha", "rust"},
			Title:       "图形验证码 + PoW + 余额竞态并发（单会话冻结后批量并发）",
			Pitfall:     "遇到“验证码 → PoW → 兑换”链路：每次请求 /captcha 会刷新 session 验证码，必须只拉 1 次保存本地并用 ddddocr 识别完成 /verify，随后离线批量预计算多组满足前缀的 nonce:sol PoW，最后在同一时刻并发发送 /redeem 触发 TOCTOU 双花。",
			PatternCode: "ocr = ddddocr.DdddOcr(show_ad=False); code = ocr.classification(img_bytes)",
		},
	}
	for _, c := range defaults {
		if existing[strings.ToLower(strings.TrimSpace(c.Title))] {
			continue
		}
		if _, err := d.CreateTipCard(ctx, c); err != nil {
			return err
		}
	}
	return nil
}

// SeedTipsFromFile idempotently imports TipCard entries from a JSON array file (e.g. bundled
// local arsenal /app/tips-seed.json in hosted benchmark images), deduplicating by lowercase
// trimmed title and stripping source_task_id so cards load cleanly into fresh databases.
func (d *DB) SeedTipsFromFile(ctx context.Context, path string) (int, error) {
	if d == nil {
		return 0, nil
	}
	path = strings.TrimSpace(path)
	if path == "" || os.Getenv("P3Y_SKIP_BUILTIN_TIPS") == "1" {
		return 0, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return 0, nil
	}
	var cards []TipCard
	if err := json.Unmarshal([]byte(trimmed), &cards); err != nil {
		return 0, fmt.Errorf("parse tips seed %s: %w", path, err)
	}
	if len(cards) == 0 {
		return 0, nil
	}
	existing := map[string]bool{}
	rows, err := d.QueryContext(ctx, `SELECT LOWER(TRIM(title)) FROM tips_cards`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var title string
		if rows.Scan(&title) == nil && title != "" {
			existing[title] = true
		}
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	inserted := 0
	for _, c := range cards {
		key := strings.ToLower(strings.TrimSpace(c.Title))
		if key == "" || existing[key] {
			continue
		}
		// Never carry over source_task_id from another deployment (FK would fail on a fresh DB).
		c.ID = 0
		c.SourceTaskID = nil
		if _, err := d.CreateTipCard(ctx, c); err != nil {
			return inserted, err
		}
		existing[key] = true
		inserted++
	}
	return inserted, nil
}
