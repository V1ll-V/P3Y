package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"p3y/ctf"
	"p3y/db"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

type (
	ctfForkRunnerKey struct{}
	ctfForkSubKey    struct{}
)

// CTFBranchSpec defines a single competing hypothesis for Plateau Fork execution.
type CTFBranchSpec struct {
	Name       string `json:"name"`
	Hypothesis string `json:"hypothesis"`
	CheckCmd   string `json:"check_cmd,omitempty"`
}

// CTFPlateauForkRequest configures parallel branch exploration after repeated rewinds.
type CTFPlateauForkRequest struct {
	SavepointID int64           `json:"savepoint_id,omitempty"`
	Branches    []CTFBranchSpec `json:"branches"`
	MaxTurns    int             `json:"max_turns,omitempty"`
}

// CTFBranchOutcome records one branch's execution and oracle result.
type CTFBranchOutcome struct {
	Name      string `json:"name"`
	WorkDir   string `json:"work_dir,omitempty"`
	Success   bool   `json:"success"`
	Verified  bool   `json:"verified"`
	Summary   string `json:"summary"`
	ElapsedMs int64  `json:"elapsed_ms"`
	DeadendID int64  `json:"deadend_id,omitempty"`
	Error     string `json:"error,omitempty"`
}

// CTFPlateauForkResult summarizes all competing branches and any promoted winner.
type CTFPlateauForkResult struct {
	ForkID        string             `json:"fork_id"`
	SavepointID   int64              `json:"savepoint_id,omitempty"`
	Winner        string             `json:"winner,omitempty"`
	WinnerWorkDir string             `json:"winner_work_dir,omitempty"`
	Promoted      bool               `json:"promoted"`
	BoardFactID   int64              `json:"board_fact_id,omitempty"`
	Branches      []CTFBranchOutcome `json:"branches"`
}

// CTFPlateauForkRunner executes competing branches in parallel.
type CTFPlateauForkRunner func(ctx context.Context, req CTFPlateauForkRequest) (CTFPlateauForkResult, error)

// WithCTFPlateauForkRunner attaches the Plateau Fork orchestrator to ctx.
func WithCTFPlateauForkRunner(ctx context.Context, fn CTFPlateauForkRunner) context.Context {
	if fn == nil {
		return ctx
	}
	return context.WithValue(ctx, ctfForkRunnerKey{}, fn)
}

func ctfPlateauForkRunnerFromContext(ctx context.Context) CTFPlateauForkRunner {
	if ctx == nil {
		return nil
	}
	fn, _ := ctx.Value(ctfForkRunnerKey{}).(CTFPlateauForkRunner)
	return fn
}

func isCTFForkBranchContext(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	v, _ := ctx.Value(ctfForkSubKey{}).(bool)
	return v
}

const ctfForkBranchSystem = `【思考与输出语言规范】思考与输出请全程使用简体中文（命令、代码、路径与专有术语除外）。

你是「停滞分叉（Plateau Fork）」并行竞争分支之一，只验证指派给你的**唯一假设分支**。
1. **工作区隔离铁律**：你的专属隔离工作区路径在首轮消息中指定（/work/.forks/<fork_id>/<branch>）；所有脚本编写、修改与调试均必须在该目录内完成，严禁修改 /work/.inputs 或其他分支目录。
2. 原始只读附件位于 /work/.inputs，可直接读取。
3. 若分支提供了 check_cmd 验真命令，你的目标是修改/编写脚本使该 check_cmd 在你的专属目录中返回 exit 0；验证通过或得出明确证伪结论后，立刻停止并在末轮简短汇报（<800 字）。`

func stripForkBranchTools(tools []actool.CoreTool) []actool.CoreTool {
	out := make([]actool.CoreTool, 0, len(tools))
	for _, t := range tools {
		switch t.Name() {
		case "ask_helper", "plateau_fork", "board_mark_savepoint", "board_rewind":
			continue
		}
		out = append(out, t)
	}
	return out
}

func plateauForkTool() actool.CoreTool {
	return writeTool("plateau_fork", "在同一 Savepoint 多次读档回滚进入停滞期后，基于存档快照并发派生 2~3 个隔离工作区分支并行验证不同利用假设；最先通过验真的胜出分支会自动合并回 /work，其余分支取消并自动沉淀 Deadend 约束。", obj(map[string]any{
		"savepoint_id": intp("可选基准 Savepoint ID；留空则自动选取当前任务最新 Savepoint（若无则基于当前 /work）"),
		"branches": map[string]any{
			"type": "array",
			"items": obj(map[string]any{
				"name":       str("分支短名（如 'ret2libc'、'srop'、'sqli_time'）"),
				"hypothesis": str("本分支要独立验证的技术假设与操作思路"),
				"check_cmd":  str("可选 0-LLM 验真命令（会在该分支隔离目录中执行，exit 0 即判胜出）"),
			}, "name", "hypothesis"),
			"description": "并发对比的 2~3 条互不依赖假设分支",
		},
		"max_turns": intp("每分支最大轮数预算（范围 3~10，默认 8）"),
	}, "branches"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		if isCTFForkBranchContext(ctx) || isCTFHelperContext(ctx) {
			return actool.Errorf("子分支或 Helper 内禁止嵌套调用 plateau_fork"), nil
		}
		runner := ctfPlateauForkRunnerFromContext(ctx)
		if runner == nil {
			return actool.Errorf("当前运行上下文未挂载 Plateau Fork 调度器"), nil
		}
		var req CTFPlateauForkRequest
		if err := json.Unmarshal(in, &req); err != nil {
			return actool.Errorf(fmt.Sprintf("参数解析失败: %v", err)), nil
		}
		if len(req.Branches) < 2 || len(req.Branches) > 3 {
			return actool.Errorf(fmt.Sprintf("plateau_fork 必须提供 2~3 个竞争分支（当前 %d 个）", len(req.Branches))), nil
		}
		for i, br := range req.Branches {
			if strings.TrimSpace(br.Name) == "" || strings.TrimSpace(br.Hypothesis) == "" {
				return actool.Errorf(fmt.Sprintf("branches[%d] 的 name 与 hypothesis 均不能为空", i)), nil
			}
		}
		res, err := runner(ctx, req)
		if err != nil {
			return actool.Errorf(fmt.Sprintf("Plateau Fork 执行失败: %v", err)), nil
		}
		b, _ := json.Marshal(res)
		return actool.Text(string(b)), nil
	})
}

func (w *Worker) runCTFPlateauFork(ctx context.Context, as *db.AssetStore, ts *db.ExplorationStore, taskID, intentID int64, runDir string, emit func(db.Activity), req CTFPlateauForkRequest) (CTFPlateauForkResult, error) {
	if w == nil || w.prov == nil {
		return CTFPlateauForkResult{}, fmt.Errorf("未配置模型 Provider")
	}
	var pg *db.DB
	if ts != nil {
		pg = ts.Database()
	}
	root := w.workDir
	ctfSvc := ctf.New(root, pg)
	if w.proxyAddr != "" || w.proxyCACert != "" {
		ctfSvc.WithProxy(w.proxyAddr, w.proxyCACert)
	}

	var spItem *db.BoardItem
	if pg != nil && taskID > 0 {
		if req.SavepointID > 0 {
			spItem, _ = pg.GetBoardItem(ctx, taskID, req.SavepointID)
		} else {
			if items, err := pg.ListBoardItems(ctx, taskID, db.BoardKindSavepoint); err == nil && len(items) > 0 {
				spItem = &items[len(items)-1]
			}
		}
	}
	spID := int64(0)
	snapID := ""
	if spItem != nil {
		spID = spItem.ID
		snapID = spItem.SnapshotID
	}

	var deadendHints []string
	if pg != nil && taskID > 0 && spID > 0 {
		if ditems, err := pg.ListBoardItems(ctx, taskID, db.BoardKindDeadend); err == nil {
			for _, d := range ditems {
				if d.ParentID != nil && *d.ParentID == spID {
					deadendHints = append(deadendHints, fmt.Sprintf("- %s: %s", d.Title, d.Summary))
				}
			}
		}
	}

	forkID := fmt.Sprintf("f%d-%d", taskID, time.Now().UnixMilli())
	names := make([]string, len(req.Branches))
	for i, br := range req.Branches {
		names[i] = br.Name
	}
	branchDirs, err := ctfSvc.PrepareForkWorkdirs(ctx, taskID, intentID, forkID, snapID, names)
	if err != nil {
		return CTFPlateauForkResult{}, err
	}

	turns := req.MaxTurns
	if turns <= 0 {
		turns = 8
	}
	if turns < 3 {
		turns = 3
	}
	if turns > 10 {
		turns = 10
	}

	forkCtx, cancelFork := context.WithCancel(ctx)
	defer cancelFork()

	var baselineCandID int64
	if pg != nil && taskID > 0 {
		if cand, err := pg.PendingCTFSubmission(ctx, taskID); err == nil && cand != nil {
			baselineCandID = cand.ID
		}
	}

	outcomes := make([]CTFBranchOutcome, len(req.Branches))
	var (
		winMu  sync.Mutex
		winner string
		winDir string
		wg     sync.WaitGroup
	)

	forkEmit := func(branchName string, r db.Activity) {
		if emit != nil {
			iid := intentID
			r.NodeID = &iid
			r.Worker = "fork:" + branchName
			emit(r)
		}
	}
	forkEmit("orchestrator", db.Activity{
		Kind:    "plateau_fork_start",
		Summary: fmt.Sprintf("Plateau Fork 启动 %d 个并发假设分支（sp=#%d）", len(req.Branches), spID),
	})

	for idx, br := range req.Branches {
		wg.Add(1)
		go func(i int, spec CTFBranchSpec) {
			defer wg.Done()
			t0 := time.Now()
			bDir := branchDirs[spec.Name]
			tsx := NewToolSet(ts, "fork:"+spec.Name)
			tsx.SetTaskID(taskID)
			if as != nil {
				tsx.SetAssetStore(as)
			}
			tsx.SetOwnerNode(intentID)

			base := append(tsx.WorkerTools(), w.extraTools...)
			base = append(base, defaultToolsExcept("MultiEdit", "Glob", "Grep")...)
			bCtx := WithRunInfo(forkCtx, RunInfo{TaskID: taskID, ExplorationID: explorationID(ts), IntentID: intentID})
			bCtx = WithCTFProxy(bCtx, w.proxyAddr, w.proxyCACert)
			bCtx = context.WithValue(bCtx, ctfForkSubKey{}, true)
			bCtx = transcript.WithSessionID(bCtx, fmt.Sprintf("exp%d-fork-%s-i%d", explorationID(ts), spec.Name, intentID))
			bCtx, base = ctfBase(bCtx, w.workDir, ts, taskID, intentID, base)
			tools, def, cleanup := AugmentTools(bCtx, "worker", base)
			defer cleanup()
			tools = stripForkBranchTools(tools)

			system, boundary := deferredSystem(ctfForkBranchSystem, def)
			var prompt strings.Builder
			fmt.Fprintf(&prompt, "【分叉假设 #%d：%s】\n你的专属隔离工作区目录：%s\n假设方案：%s\n", i+1, spec.Name, bDir, spec.Hypothesis)
			if strings.TrimSpace(spec.CheckCmd) != "" {
				fmt.Fprintf(&prompt, "验收 check_cmd：%s（系统会在 %s 下自动执行验证，exit 0 即判胜出）\n", spec.CheckCmd, bDir)
			}
			if len(deadendHints) > 0 {
				prompt.WriteString("\n【已证伪死胡同 Deadend（严禁重蹈覆辙）】\n" + strings.Join(deadendHints, "\n") + "\n")
			}
			prompt.WriteString("\n请直接在你的隔离工作区目录内完成验证并汇报结果。")

			bTimeout := 150 * time.Second
			if dl, ok := bCtx.Deadline(); ok {
				if rem := time.Until(dl); rem > 0 && rem < bTimeout {
					bTimeout = rem
				}
			}

			opts := agentcore.Options{
				Provider:        withRoleThinking(w.prov, "plateau_fork", "worker", true),
				SystemPrompt:    system,
				DynamicBoundary: boundary,
				Tools:           tools,
				DeferredTools:   def.Deferred,
				UnlockSet:       def.Unlock,
				PermissionMode:  permission.ModeBypass,
				EnableWebFetch:  false,
				WebFetchProxy:   w.proxyAddr,
				WebFetchCACert:  w.proxyCACert,
				BashEnv:         proxyEnv(w.proxyAddr, w.proxyCACert),
				WorkingDir:      runDir,
				MaxTurns:        turns,
				MaxDuration:     bTimeout,
				ToolOutputDir:   cmdOutDir(runDir),
				Compaction:      compactionConfig(w.compactionWindow()),
				NonStreaming:    w.nonStreaming(),
				MaxTokens:       w.maxTokens(),
				Settlement:      &harness.Settlement{Prompt: "已达分支轮次预算，请简短汇报当前分支成功/失败结论与依据。", MaxTurns: 1, DisabledTools: ctfExecutionTools},
			}

			branchEmit := func(r db.Activity) { forkEmit(spec.Name, r) }
			text, reason, runErr := captureRun(bCtx, opts, prompt.String(), branchEmit)
			outcome := CTFBranchOutcome{
				Name:      spec.Name,
				WorkDir:   bDir,
				Summary:   truncOutput(strings.TrimSpace(text), 900),
				ElapsedMs: time.Since(t0).Milliseconds(),
			}
			if runErr != nil {
				outcome.Error = runErr.Error()
			}

			// Deterministic victory check: check_cmd in branch dir OR newly found candidate Flag/Proof.
			won := false
			if forkCtx.Err() == nil && runErr == nil {
				if strings.TrimSpace(spec.CheckCmd) != "" {
					chkCmd := fmt.Sprintf("cd %s && %s", quoteShellPath(bDir), spec.CheckCmd)
					if chk, cerr := ctfSvc.VerifyCheck(forkCtx, taskID, intentID, chkCmd, 45); cerr == nil && chk.Passed {
						won = true
						outcome.Verified = true
					}
				} else if pg != nil && taskID > 0 {
					if cand, cerr := pg.PendingCTFSubmission(forkCtx, taskID); cerr == nil && cand != nil && cand.ID > baselineCandID {
						won = true
						outcome.Verified = true
					}
				}
				if !won && strings.TrimSpace(spec.CheckCmd) == "" && reason == harness.ReasonCompleted && strings.Contains(strings.ToUpper(outcome.Summary), "SUCCESS") {
					won = true
				}
			}
			outcome.Success = won

			if won {
				winMu.Lock()
				if winner == "" {
					winner = spec.Name
					winDir = bDir
					cancelFork() // Stop slower sibling branches once a verified winner emerges.
				}
				winMu.Unlock()
			}
			outcomes[i] = outcome
		}(idx, br)
	}
	wg.Wait()

	res := CTFPlateauForkResult{
		ForkID:        forkID,
		SavepointID:   spID,
		Winner:        winner,
		WinnerWorkDir: winDir,
		Branches:      outcomes,
	}

	if winner != "" {
		if err := ctfSvc.PromoteForkBranch(ctx, taskID, intentID, forkID, winner); err == nil {
			res.Promoted = true
		}
		if pg != nil && taskID > 0 {
			var pPtr *int64
			if spID > 0 {
				pPtr = &spID
			}
			metaBytes, _ := json.Marshal(res)
			if item, ierr := pg.AddBoardItem(ctx, db.BoardItem{
				TaskID:   taskID,
				ParentID: pPtr,
				Kind:     db.BoardKindFact,
				Title:    fmt.Sprintf("[Plateau Fork 胜出] %s", winner),
				Summary:  fmt.Sprintf("并发验证 %d 个假设分支后由 %s 胜出并合并回 /work", len(outcomes), winner),
				Detail:   string(metaBytes),
				Verified: true,
				Meta:     metaBytes,
			}); ierr == nil && item != nil {
				res.BoardFactID = item.ID
			}
		}
	}

	// Record Deadends under the savepoint for branches that failed or errored (excluding cancelled losers once a winner already solved it).
	if pg != nil && taskID > 0 && spID > 0 {
		pPtr := spID
		for i := range outcomes {
			o := &outcomes[i]
			if o.Success || (winner != "" && strings.Contains(o.Error, "context canceled")) {
				continue
			}
			reasonText := o.Summary
			if o.Error != "" {
				reasonText = o.Error + " | " + reasonText
			}
			if reasonText == "" {
				reasonText = "并发分支未能通过验证"
			}
			if d, derr := pg.AddBoardItem(ctx, db.BoardItem{
				TaskID:   taskID,
				ParentID: &pPtr,
				Kind:     db.BoardKindDeadend,
				Title:    fmt.Sprintf("fork_%s_failed", o.Name),
				Summary:  truncOutput(reasonText, 240),
				Detail:   o.Summary,
				Verified: true,
			}); derr == nil && d != nil {
				o.DeadendID = d.ID
			}
		}
	}

	forkEmit("orchestrator", db.Activity{
		Kind:    "plateau_fork_done",
		Summary: fmt.Sprintf("Plateau Fork 结束：winner=%q promoted=%v", res.Winner, res.Promoted),
	})
	return res, nil
}

func quoteShellPath(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}
