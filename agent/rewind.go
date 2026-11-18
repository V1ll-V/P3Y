package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"p3y/db"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
)

type ctfRewindContextKey struct{}

type pendingRewindReq struct {
	SavepointID    int64
	SavepointTitle string
	DeadendTitle   string
	DeadendReason  string
	RewindCount    int
}

// ctfRewindController bridges board_mark_savepoint / board_rewind with the LLM
// harness loop so rewinding a workspace Savepoint also slices the conversation
// working set back to the clean prefix at that Savepoint (via a non-destructive
// CompactBoundary) and appends a single Deadend constraint.
type ctfRewindController struct {
	mu          sync.Mutex
	inner       harness.Compactor
	snapshotDir string
	sessionID   string
	pg          *db.DB
	taskID      int64
	emit        func(db.Activity)

	pendingSP int64
	spStore   map[int64][]llm.Message
	pendingRW *pendingRewindReq
}

type ctfRewindControllerWithView struct {
	*ctfRewindController
	view harness.ContextView
}

func (v *ctfRewindControllerWithView) View(ctx context.Context, msgs []llm.Message) []llm.Message {
	return v.view.View(ctx, msgs)
}

func newCTFRewindController(inner harness.Compactor, snapshotDir, sessionID string, pg *db.DB, taskID int64, emit func(db.Activity)) *ctfRewindController {
	return &ctfRewindController{
		inner:       inner,
		snapshotDir: strings.TrimSpace(snapshotDir),
		sessionID:   strings.TrimSpace(sessionID),
		pg:          pg,
		taskID:      taskID,
		emit:        emit,
		spStore:     map[int64][]llm.Message{},
	}
}

func wrapCompactorWithRewind(ctrl *ctfRewindController) harness.Compactor {
	if ctrl == nil {
		return nil
	}
	if view, ok := ctrl.inner.(harness.ContextView); ok {
		return &ctfRewindControllerWithView{ctfRewindController: ctrl, view: view}
	}
	return ctrl
}

func withCTFRewindController(ctx context.Context, ctrl *ctfRewindController) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctrl == nil {
		return ctx
	}
	return context.WithValue(ctx, ctfRewindContextKey{}, ctrl)
}

func ctfRewindFromContext(ctx context.Context) *ctfRewindController {
	if ctx == nil {
		return nil
	}
	ctrl, _ := ctx.Value(ctfRewindContextKey{}).(*ctfRewindController)
	return ctrl
}

// MarkSavepointPending flags spID so its full paired API working set (including
// board_mark_savepoint's tool_result) is captured right after the current turn.
func (c *ctfRewindController) MarkSavepointPending(spID int64) {
	if c == nil || spID <= 0 {
		return
	}
	c.mu.Lock()
	c.pendingSP = spID
	c.mu.Unlock()
}

// RequestRewind queues a conversation rewind to spID that takes effect before the
// next model request in the harness loop.
func (c *ctfRewindController) RequestRewind(spID int64, spTitle, deadendTitle, deadendReason string, rwCount int) {
	if c == nil || spID <= 0 {
		return
	}
	c.mu.Lock()
	c.pendingRW = &pendingRewindReq{
		SavepointID:    spID,
		SavepointTitle: strings.TrimSpace(spTitle),
		DeadendTitle:   strings.TrimSpace(deadendTitle),
		DeadendReason:  strings.TrimSpace(deadendReason),
		RewindCount:    rwCount,
	}
	c.mu.Unlock()
}

// FlushPendingSavepoint captures a pending Savepoint snapshot when the session is
// stopping before another Pre() turn runs.
func (c *ctfRewindController) FlushPendingSavepoint(ctx context.Context, msgs []llm.Message) {
	if c == nil {
		return
	}
	c.mu.Lock()
	spID := c.pendingSP
	c.pendingSP = 0
	c.mu.Unlock()
	if spID > 0 {
		c.captureSnapshot(ctx, spID, msgs)
	}
}

func (c *ctfRewindController) Pre(ctx context.Context, msgs []llm.Message, lastInputTokens int) []llm.Message {
	c.mu.Lock()
	spID := c.pendingSP
	c.pendingSP = 0
	rw := c.pendingRW
	c.pendingRW = nil
	c.mu.Unlock()

	if spID > 0 {
		c.captureSnapshot(ctx, spID, msgs)
	}

	if rw != nil {
		if prefix := c.loadSnapshot(rw.SavepointID); len(prefix) > 0 {
			workingLen := len(llm.MessagesForAPI(msgs))
			dropped := max(0, workingLen-len(prefix))
			boundary := llm.BoundaryMessage(llm.BoundaryMeta{
				Trigger:            "rewind",
				MessagesSummarized: dropped,
			})
			notice := formatRewindNotice(rw)
			out := make([]llm.Message, 0, len(msgs)+len(prefix)+2)
			out = append(out, msgs...)
			out = append(out, boundary)
			out = append(out, cloneLLMMessages(prefix)...)
			out = append(out, llm.UserText(notice))
			if c.emit != nil {
				c.emit(db.Activity{
					Worker:  "worker",
					Kind:    "board_rewind",
					Summary: fmt.Sprintf("对话与工作区联合回滚至 Savepoint #%d（保留 %d 条前置消息，剪除 %d 条失败试错）", rw.SavepointID, len(prefix), dropped),
				})
			}
			// Reset lastInputTokens to 0 so the inner compactor does not trigger on
			// token counts from the discarded dead-end branch.
			if c.inner != nil {
				return c.inner.Pre(ctx, out, 0)
			}
			return out
		}
	}

	if c.inner != nil {
		return c.inner.Pre(ctx, msgs, lastInputTokens)
	}
	return msgs
}

func (c *ctfRewindController) Reactive(ctx context.Context, msgs []llm.Message) ([]llm.Message, bool) {
	if c.inner != nil {
		return c.inner.Reactive(ctx, msgs)
	}
	return msgs, false
}

func (c *ctfRewindController) IsOverflow(err error) bool {
	if c.inner != nil {
		return c.inner.IsOverflow(err)
	}
	return false
}

func (c *ctfRewindController) captureSnapshot(ctx context.Context, spID int64, msgs []llm.Message) {
	working := cloneLLMMessages(llm.MessagesForAPI(msgs))
	if len(working) == 0 {
		return
	}
	c.mu.Lock()
	c.spStore[spID] = working
	c.mu.Unlock()

	if path := c.snapshotPath(spID); path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err == nil {
			if raw, err := json.Marshal(working); err == nil {
				_ = os.WriteFile(path, raw, 0o600)
			}
		}
	}
	if c.pg != nil && c.taskID > 0 {
		patch := map[string]any{"msg_cursor": len(working)}
		if c.sessionID != "" {
			patch["session_id"] = c.sessionID
		}
		_ = c.pg.PatchBoardItemMeta(ctx, c.taskID, spID, patch)
	}
}

func (c *ctfRewindController) loadSnapshot(spID int64) []llm.Message {
	c.mu.Lock()
	cached := c.spStore[spID]
	c.mu.Unlock()
	if len(cached) > 0 {
		return cached
	}
	path := c.snapshotPath(spID)
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var loaded []llm.Message
	if json.Unmarshal(raw, &loaded) != nil || len(loaded) == 0 {
		return nil
	}
	c.mu.Lock()
	c.spStore[spID] = loaded
	c.mu.Unlock()
	return loaded
}

func (c *ctfRewindController) snapshotPath(spID int64) string {
	if c.snapshotDir == "" || c.sessionID == "" || spID <= 0 {
		return ""
	}
	return filepath.Join(c.snapshotDir, fmt.Sprintf("%s-sp%d.json", c.sessionID, spID))
}

func formatRewindNotice(rw *pendingRewindReq) string {
	var b strings.Builder
	fmt.Fprintf(&b, "【系统时光回滚已完成】工作区 /work 与对话记忆已原子回滚至 Savepoint #%d（%s，累计回滚 %d 次）。\n",
		rw.SavepointID, rw.SavepointTitle, rw.RewindCount)
	b.WriteString("从该存档点出发的分支已被证伪并记录为 Deadend 禁区：\n")
	fmt.Fprintf(&b, "- [%s] %s\n", rw.DeadendTitle, rw.DeadendReason)
	b.WriteString("请直接基于当前干净工作区与上述正确前置上下文切换其它思路；严禁再重复已标记的 Deadend 方向。")
	if rw.RewindCount >= 2 {
		fmt.Fprintf(&b, "\n提示：同一 Savepoint 已回滚达 %d 次（plateau_detected=true），建议优先调用 plateau_fork 并发验证 2~3 条互不依赖的假设分支。", rw.RewindCount)
	}
	return b.String()
}

func cloneLLMMessages(in []llm.Message) []llm.Message {
	if len(in) == 0 {
		return nil
	}
	out := make([]llm.Message, len(in))
	for i, m := range in {
		var blocks []llm.ContentBlock
		if len(m.Content) > 0 {
			blocks = make([]llm.ContentBlock, len(m.Content))
			for j, b := range m.Content {
				blocks[j] = cloneContentBlock(b)
			}
		}
		out[i] = llm.Message{Role: m.Role, Content: blocks}
	}
	return out
}

func cloneContentBlock(b llm.ContentBlock) llm.ContentBlock {
	if len(b.Input) > 0 {
		cp := make([]byte, len(b.Input))
		copy(cp, b.Input)
		b.Input = cp
	}
	if len(b.Content) > 0 {
		sub := make([]llm.ContentBlock, len(b.Content))
		for i, c := range b.Content {
			sub[i] = cloneContentBlock(c)
		}
		b.Content = sub
	}
	return b
}

type ctfRewindHooks struct {
	inner harness.HookRunner
	ctrl  *ctfRewindController
}

func (h ctfRewindHooks) PreToolUse(ctx context.Context, name string, input []byte) (bool, string, []byte) {
	if h.inner != nil {
		return h.inner.PreToolUse(ctx, name, input)
	}
	return false, "", nil
}

func (h ctfRewindHooks) PostToolUse(ctx context.Context, name string, input, result []byte, isErr bool) {
	if h.inner != nil {
		h.inner.PostToolUse(ctx, name, input, result, isErr)
	}
}

func (h ctfRewindHooks) Stop(ctx context.Context, messages []llm.Message) (bool, []string, string) {
	if h.ctrl != nil {
		h.ctrl.FlushPendingSavepoint(ctx, messages)
	}
	if h.inner != nil {
		return h.inner.Stop(ctx, messages)
	}
	return false, nil, ""
}
