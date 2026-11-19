package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"p3y/ctf"
	actool "github.com/Autumn-27/norma/tool"
)

func boolp(desc string) map[string]any {
	return map[string]any{"type": "boolean", "description": desc}
}

func ctfNeuroTools(s *ctf.Service, task, intent int64) []actool.CoreTool {
	return []actool.CoreTool{
		writeTool("http_fuzz_diff", "批量并行探测一组 HTTP payload（最多 64 个）并自动与基准响应做聚类对比，仅高亮状态码/长度/正文 diff/耗时异常/报错特征的差异样本。", obj(map[string]any{
			"url":              str("目标 URL；可在路径或查询串中使用 {FUZZ} 占位符，或配合 param 字段注入"),
			"method":           str("HTTP 方法：GET | POST | HEAD | PUT | PATCH | DELETE，默认 GET（有 body_template 时默认 POST）"),
			"param":            str("未写 {FUZZ} 时自动替换或编码的表单/查询参数名"),
			"headers":          map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "自定义请求头，值内支持 {FUZZ}"},
			"body_template":    str("请求体模板，支持 {FUZZ} 占位符（如 '{\"id\":\"{FUZZ}\"}'）"),
			"cookies":          map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "附加 Cookie 键值对"},
			"payloads":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "待测试 payload 列表（1~64 条）"},
			"baseline_payload": str("可选基准对照值，默认使用无害随机探针"),
			"timeout_seconds":  intp("单请求超时秒数，默认 10，最大 60"),
			"max_workers":      intp("并发线程数，默认 6，最大 16"),
			"follow_redirects": boolp("是否跟随重定向，默认 false"),
		}, "url", "payloads"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s == nil {
				return actool.Errorf("http_fuzz_diff 仅在 CTF 沙箱上下文可用"), nil
			}
			var spec ctf.HTTPFuzzDiffSpec
			if err := json.Unmarshal(in, &spec); err != nil {
				return actool.Errorf(fmt.Sprintf("参数解析失败: %v", err)), nil
			}
			cmd, timeout, err := ctf.BuildHTTPFuzzDiffCommand(spec)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			e, err := s.Execute(ctx, task, intent, cmd, timeout)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			b, _ := json.Marshal(e)
			return actool.Text(string(b)), nil
		}),

		writeTool("diff_local_remote", "对比同一脚本/命令在本地与远端靶机的执行行为，自动对齐退出码、耗时、泄露十六进制地址、崩溃/EOF 信号、unified diff 及定位提示。", obj(map[string]any{
			"script_path":     str("工作区内的对比脚本路径（如 '/work/exp.py'，分别传 local_args 与 remote_args 执行）"),
			"local_args":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "传给本地执行的参数列表（如 ['LOCAL']）"},
			"remote_args":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "传给远端执行的参数列表（如 ['REMOTE']）"},
			"local_cmd":       str("不使用 script_path 时可直接指定完整本地 shell 命令"),
			"remote_cmd":      str("不使用 script_path 时可直接指定完整远端 shell 命令"),
			"local_env":       map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "本地运行附加环境变量"},
			"remote_env":      map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "远端运行附加环境变量"},
			"stdin_text":      str("可选同时喂给两侧进程的标准输入文本"),
			"timeout_seconds": intp("单侧超时秒数，默认 15，最大 60"),
		}), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s == nil {
				return actool.Errorf("diff_local_remote 仅在 CTF 沙箱上下文可用"), nil
			}
			var spec ctf.DiffLocalRemoteSpec
			if err := json.Unmarshal(in, &spec); err != nil {
				return actool.Errorf(fmt.Sprintf("参数解析失败: %v", err)), nil
			}
			spec.ScriptPath = s.TranslateSandboxWorkPaths(ctx, task, intent, spec.ScriptPath)
			spec.LocalCmd = s.TranslateSandboxWorkPaths(ctx, task, intent, spec.LocalCmd)
			spec.RemoteCmd = s.TranslateSandboxWorkPaths(ctx, task, intent, spec.RemoteCmd)
			for i := range spec.LocalArgs {
				spec.LocalArgs[i] = s.TranslateSandboxWorkPaths(ctx, task, intent, spec.LocalArgs[i])
			}
			for i := range spec.RemoteArgs {
				spec.RemoteArgs[i] = s.TranslateSandboxWorkPaths(ctx, task, intent, spec.RemoteArgs[i])
			}
			cmd, timeout, err := ctf.BuildDiffLocalRemoteCommand(spec)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			e, err := s.Execute(ctx, task, intent, cmd, timeout)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			b, _ := json.Marshal(e)
			return actool.Text(string(b)), nil
		}),

		writeTool("py_repl", "在容器内持久状态化 Python 3 REPL 中执行表达式或代码段，预置 math/struct/hashlib/z3/gmpy2/Crypto/pwn，变量与对象在多轮调用间常驻内存。", obj(map[string]any{
			"code":            str("要执行的 Python 代码；末行为表达式时自动返回 repr 结果"),
			"session":         str("可选 REPL 会话名（默认 default），同一会话共享全局变量"),
			"reset":           boolp("是否先重置清空该 REPL 会话再执行（默认 false）"),
			"timeout_seconds": intp("单次求值超时秒数（默认 20，最大 120）"),
		}), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s == nil {
				return actool.Errorf("py_repl 仅在 CTF 沙箱上下文可用"), nil
			}
			var a struct {
				Code           string `json:"code"`
				Session        string `json:"session"`
				Reset          bool   `json:"reset"`
				TimeoutSeconds int    `json:"timeout_seconds"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(fmt.Sprintf("参数解析失败: %v", err)), nil
			}
			if !a.Reset && strings.TrimSpace(a.Code) == "" {
				return actool.Errorf("code 不能为空（除非仅传 reset=true）"), nil
			}
			res, err := s.EvalPyREPL(ctx, task, intent, a.Session, a.Code, a.Reset, a.TimeoutSeconds)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			b, _ := json.Marshal(res)
			return actool.Text(string(b)), nil
		}),

		writeTool("http_race_probe", "使用线程 Barrier 预建连并同时并发齐射 HTTP 请求（2~40 并发），按状态码/长度/正文哈希聚类统计并发窗口内的竞态（Race Condition / TOCTOU）异常。", obj(map[string]any{
			"url":             str("目标 URL"),
			"method":          str("HTTP 方法：GET | POST | PUT | PATCH | DELETE | HEAD，默认有 body 时 POST"),
			"headers":         map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "请求头键值对"},
			"body":            str("请求体文本"),
			"cookies":         map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "Cookie 键值对"},
			"pre_url":         str("可选前置准备/重置请求的 URL（在并发齐射前先单次请求）"),
			"pre_method":      str("可选前置请求方法"),
			"pre_body":        str("可选前置请求正文"),
			"concurrency":     intp("并发齐射请求数（2~40，默认 20）"),
			"timeout_seconds": intp("单请求超时秒数（默认 10，最大 30）"),
		}, "url"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s == nil {
				return actool.Errorf("http_race_probe 仅在 CTF 沙箱上下文可用"), nil
			}
			var spec ctf.HTTPRaceProbeSpec
			if err := json.Unmarshal(in, &spec); err != nil {
				return actool.Errorf(fmt.Sprintf("参数解析失败: %v", err)), nil
			}
			cmd, timeout, err := ctf.BuildHTTPRaceProbeCommand(spec)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			e, err := s.Execute(ctx, task, intent, cmd, timeout)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			b, _ := json.Marshal(e)
			return actool.Text(string(b)), nil
		}),
	}
}
