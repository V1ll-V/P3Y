package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"time"

	"p3y/ctf"
	"p3y/db"
	actool "github.com/Autumn-27/norma/tool"
)

func ctfBoardTools(s *ctf.Service, pg *db.DB, task, intent int64) []actool.CoreTool {
	strVal := func(a map[string]json.RawMessage, k string) string {
		var v string
		_ = json.Unmarshal(a[k], &v)
		return strings.TrimSpace(v)
	}
	int64Val := func(a map[string]json.RawMessage, k string) int64 {
		var v int64
		_ = json.Unmarshal(a[k], &v)
		return v
	}

	return []actool.CoreTool{
		writeTool("board_mark_savepoint", "通过 0-LLM Check 确定性验真后，冻结当前容器 /work 工作区快照并创建里程碑存档点 Savepoint。", obj(map[string]any{
			"title":       str("L1 存档点名称（如 'stage1_leak_verified'）"),
			"summary":     str("L2 当前阶段已验证成果说明"),
			"detail":      str("L3 可选补充细节"),
			"check_cmd":   str("确定性 0-LLM 验真命令（例如 'python3 /work/leak.py LOCAL'）；非空时必须 exit 0 才允许创建存档点"),
			"snapshot_id": str("可选自定义快照 ID（默认自动生成）"),
			"parent_id":   intp("可选父节点 ID"),
		}, "title", "summary"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s == nil || pg == nil || task <= 0 {
				return actool.Errorf("需要 CTF 沙箱与数据库上下文"), nil
			}
			var a map[string]json.RawMessage
			_ = json.Unmarshal(in, &a)
			checkCmd := strVal(a, "check_cmd")
			meta := map[string]any{}
			verified := false
			if checkCmd != "" {
				chk, err := s.VerifyCheck(ctx, task, intent, checkCmd, 60)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				meta["execution_id"] = chk.ExecutionID
				meta["check_exit_code"] = chk.ExitCode
				if !chk.Passed {
					return actool.Errorf(fmt.Sprintf("Check 验真未通过（exit=%d），拒绝创建 Savepoint；stderr=%s stdout=%s", chk.ExitCode, chk.StderrExcerpt, chk.StdoutExcerpt)), nil
				}
				verified = true
			}
			snapName := strVal(a, "snapshot_id")
			if snapName == "" {
				snapName = fmt.Sprintf("sp-t%d-%d", task, time.Now().UnixMilli())
			}
			spRes, err := s.CreateSavepoint(ctx, task, intent, snapName)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("容器快照创建失败: %v", err)), nil
			}
			meta["snapshot_path"] = spRes.Path
			metaBytes, _ := json.Marshal(meta)
			var parentPtr *int64
			if pid := int64Val(a, "parent_id"); pid > 0 {
				parentPtr = &pid
			}
			item, err := pg.AddBoardItem(ctx, db.BoardItem{
				TaskID:     task,
				ParentID:   parentPtr,
				Kind:       db.BoardKindSavepoint,
				Title:      strVal(a, "title"),
				Summary:    strVal(a, "summary"),
				Detail:     strVal(a, "detail"),
				SnapshotID: spRes.ID,
				CheckCmd:   checkCmd,
				Verified:   verified,
				Meta:       metaBytes,
			})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if rw := ctfRewindFromContext(ctx); rw != nil {
				rw.MarkSavepointPending(item.ID)
			}
			b, _ := json.Marshal(item)
			return actool.Text(string(b)), nil
		}),

		writeTool("board_rewind", "当当前分支受阻或进入死胡同时，原子回滚 /work 容器工作区至指定 Savepoint 快照，并在该存档点下记录单行 Deadend 负向约束以防重蹈覆辙。", obj(map[string]any{
			"savepoint_id":   intp("要读档回滚的 Savepoint 节点 ID"),
			"deadend_title":  str("失败路线名称（如 'one_gadget_0xe6c81_failed'）"),
			"deadend_reason": str("单行负向排除约束（说明为何失败及禁止再试该方向）"),
			"detail":         str("可选完整报错与现场信息"),
		}, "savepoint_id", "deadend_title", "deadend_reason"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s == nil || pg == nil || task <= 0 {
				return actool.Errorf("需要 CTF 沙箱与数据库上下文"), nil
			}
			var a map[string]json.RawMessage
			_ = json.Unmarshal(in, &a)
			spID := int64Val(a, "savepoint_id")
			sp, err := pg.GetBoardItem(ctx, task, spID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if sp == nil || sp.Kind != db.BoardKindSavepoint || strings.TrimSpace(sp.SnapshotID) == "" {
				return actool.Errorf(fmt.Sprintf("存档点 #%d 不存在或未绑定容器快照", spID)), nil
			}
			rwRes, err := s.Rewind(ctx, task, intent, sp.SnapshotID)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("容器读档失败: %v", err)), nil
			}
			deadend, rwCount, err := pg.RecordRewindAndDeadend(ctx, task, spID, strVal(a, "deadend_title"), strVal(a, "deadend_reason"), strVal(a, "detail"))
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			convRewound := false
			if rw := ctfRewindFromContext(ctx); rw != nil {
				rw.RequestRewind(spID, sp.Title, strVal(a, "deadend_title"), strVal(a, "deadend_reason"), rwCount)
				convRewound = true
			}
			resp := map[string]any{
				"rewound":              rwRes.Rewound,
				"conversation_rewound": convRewound,
				"snapshot_id":          sp.SnapshotID,
				"savepoint_id":         spID,
				"rewind_count":         rwCount,
				"plateau_detected":     rwCount >= 2,
				"deadend_record":       deadend,
			}
			if rwCount >= 2 {
				resp["recommendation"] = "已在同一存档点回滚多次进入停滞期，请考虑调用 plateau_fork 基于该 Savepoint 并发验证 2~3 条互不依赖的假设分支。"
			}
			b, _ := json.Marshal(resp)
			return actool.Text(string(b)), nil
		}),

		writeTool("board_save_kit", "将已验证可复用的脚本或符号文件（如 interact.py、symbols.json、exp.py）持久化沉淀为任务套件 Kit，避免后续步骤或分支重复造轮子。", obj(map[string]any{
			"name":         str("套件名称，如 'interact.py'、'symbols.json'、'exp.py'"),
			"path":         str("工作区内路径（默认 /work/<name>，必须位于 /work 下）"),
			"summary":      str("套件功能与调用接口说明"),
			"check_cmd":    str("可选 0-LLM 验证命令（如 'python3 -c \"import interact\"'）；非空时须执行通过"),
			"savepoint_id": intp("可选关联的 Savepoint ID"),
		}, "name", "summary"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if pg == nil || task <= 0 {
				return actool.Errorf("需要任务与数据库上下文"), nil
			}
			var a map[string]json.RawMessage
			_ = json.Unmarshal(in, &a)
			name := strVal(a, "name")
			if name == "" {
				return actool.Errorf("name 不能为空"), nil
			}
			kitPath := strVal(a, "path")
			if kitPath == "" {
				kitPath = path.Join("/work", name)
			}
			if !path.IsAbs(kitPath) {
				kitPath = path.Join("/work", kitPath)
			}
			kitPath = path.Clean(kitPath)
			if kitPath != "/work" && !strings.HasPrefix(kitPath, "/work/") {
				return actool.Errorf("套件路径仅允许位于 /work 工作区内"), nil
			}
			if strings.HasPrefix(kitPath, "/work/.inputs") {
				return actool.Errorf("原始附件 /work/.inputs 不可作为 Kit 修改目录，请先复制到 /work"), nil
			}
			checkCmd := strVal(a, "check_cmd")
			verified := false
			meta := map[string]any{}
			if checkCmd != "" {
				if s == nil {
					return actool.Errorf("执行 check_cmd 需要 CTF 沙箱上下文"), nil
				}
				chk, err := s.VerifyCheck(ctx, task, intent, checkCmd, 60)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				meta["check_cmd"] = checkCmd
				meta["execution_id"] = chk.ExecutionID
				if !chk.Passed {
					return actool.Errorf(fmt.Sprintf("Kit Check 验真失败（exit=%d）：%s", chk.ExitCode, chk.StderrExcerpt)), nil
				}
				verified = true
			}
			sha, content := "", ""
			if s != nil {
				sha, content = s.ReadWorkspaceFileSnapshot(ctx, task, intent, kitPath, 128*1024)
			}
			metaBytes, _ := json.Marshal(meta)
			var spPtr *int64
			if sp := int64Val(a, "savepoint_id"); sp > 0 {
				spPtr = &sp
			}
			kit, err := pg.UpsertBoardKit(ctx, db.BoardKit{
				TaskID:      task,
				SavepointID: spPtr,
				Name:        name,
				Path:        kitPath,
				Summary:     strVal(a, "summary"),
				Content:     content,
				SHA256:      sha,
				Verified:    verified,
				Meta:        metaBytes,
			})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			b, _ := json.Marshal(kit)
			return actool.Text(string(b)), nil
		}),

		readTool("tips_search", "按题型和特征标签检索历史沉淀的 Tips 避坑卡与成熟代码模板。", obj(map[string]any{
			"category": str("题型分类：pwn | reverse | web | crypto | misc | ad | auto"),
			"tags": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "特征标签数组，如 [\"amd64\", \"stack_alignment\", \"libc\"]",
			},
			"limit": intp("最多返回条数，默认 5，最多 10"),
		}), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if pg == nil {
				return actool.Errorf("需要数据库上下文"), nil
			}
			var a struct {
				Category string   `json:"category"`
				Tags     []string `json:"tags"`
				Limit    int      `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			limit := a.Limit
			if limit <= 0 || limit > 10 {
				limit = 5
			}
			cards, err := pg.SearchTips(ctx, a.Category, a.Tags, limit)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			for _, c := range cards {
				_ = pg.RecordTaskTipHit(ctx, task, c.ID)
			}
			b, _ := json.Marshal(cards)
			return actool.Text(string(b)), nil
		}),
	}
}
