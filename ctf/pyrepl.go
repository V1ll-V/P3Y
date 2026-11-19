package ctf

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// PyREPLResult represents one stateful evaluation result from a container py_repl session.
type PyREPLResult struct {
	Session string            `json:"session"`
	Repr    string            `json:"repr,omitempty"`
	Stdout  string            `json:"stdout,omitempty"`
	Stderr  string            `json:"stderr,omitempty"`
	Error   string            `json:"error,omitempty"`
	Vars    map[string]string `json:"vars,omitempty"`
	Reset   bool              `json:"reset,omitempty"`
}

var replSessionSanitizeRe = regexp.MustCompile(`[^a-zA-Z0-9_-]+`)

func sanitizeREPLSession(name string) string {
	s := replSessionSanitizeRe.ReplaceAllString(strings.TrimSpace(name), "-")
	s = strings.Trim(s, "-")
	if s == "" {
		return "default"
	}
	if len(s) > 24 {
		s = s[:24]
	}
	return s
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

const pyREPLServerScript = `import ast, base64, contextlib, io, json, sys, traceback

ns = {"__name__": "__p3y_repl__"}
for _mod in ("math", "struct", "json", "re", "hashlib", "base64", "binascii", "itertools"):
    try:
        ns[_mod] = __import__(_mod)
    except Exception:
        pass
try:
    import z3
    ns["z3"] = z3
except Exception:
    pass
try:
    import gmpy2
    ns["gmpy2"] = gmpy2
except Exception:
    pass
try:
    from Crypto.Util import number as crypto_number
    ns["bytes_to_long"] = crypto_number.bytes_to_long
    ns["long_to_bytes"] = crypto_number.long_to_bytes
except Exception:
    pass
try:
    import pwn
    pwn.context.log_level = "warning"
    ns["pwn"] = pwn
except Exception:
    pass

_BASE_KEYS = set(ns.keys())
sys.stdout.write("__P3Y_REPL_READY__\n")
sys.stdout.flush()

while True:
    line = sys.stdin.readline()
    if not line:
        break
    line = line.strip()
    if not line:
        continue
    req_id = ""
    res = {"stdout": "", "stderr": "", "repr": "", "error": "", "vars": {}}
    try:
        req = json.loads(line)
        req_id = str(req.get("id", ""))
        code = base64.b64decode(req.get("code_b64", "")).decode("utf-8")
        out_buf, err_buf = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
            tree = ast.parse(code, "<py_repl>", "exec")
            if tree.body and isinstance(tree.body[-1], ast.Expr):
                last_expr = ast.Expression(tree.body[-1].value)
                body_stmts = ast.Module(tree.body[:-1], type_ignores=[])
                if body_stmts.body:
                    exec(compile(body_stmts, "<py_repl>", "exec"), ns)
                val = eval(compile(last_expr, "<py_repl>", "eval"), ns)
                if val is not None:
                    res["repr"] = repr(val)[:4000]
            else:
                exec(compile(tree, "<py_repl>", "exec"), ns)
        res["stdout"] = out_buf.getvalue()[:8000]
        res["stderr"] = err_buf.getvalue()[:4000]
        user_vars = {}
        for k in sorted(ns.keys()):
            if k.startswith("_") or k in _BASE_KEYS:
                continue
            v = ns[k]
            if callable(v) and getattr(v, "__module__", "") not in ("__p3y_repl__", ""):
                continue
            r = repr(v)
            if len(r) > 120:
                r = r[:117] + "..."
            user_vars[k] = f"{type(v).__name__}={r}"
            if len(user_vars) >= 24:
                break
        res["vars"] = user_vars
    except Exception:
        res["error"] = traceback.format_exc()[-3000:]
    sys.stdout.write(f"__P3Y_REPL_DONE__:{req_id}:{json.dumps(res, ensure_ascii=False)}\n")
    sys.stdout.flush()
`

// EvalPyREPL executes code inside a persistent stateful Python 3 REPL session inside the
// CTF container so Z3/Crypto/pwntools/struct variables stay resident across turns.
func (s *Service) EvalPyREPL(ctx context.Context, task, intent int64, session, code string, reset bool, timeoutSec int) (*PyREPLResult, error) {
	if s == nil {
		return nil, fmt.Errorf("CTF 沙箱上下文未就绪")
	}
	code = s.TranslateSandboxWorkPaths(ctx, task, intent, code)
	code = strings.TrimSpace(code)
	if !reset && code == "" {
		return nil, fmt.Errorf("code 不能为空（除非仅传 reset=true 重置会话）")
	}
	if timeoutSec <= 0 {
		timeoutSec = 20
	}
	if timeoutSec > 120 {
		timeoutSec = 120
	}
	cleanSess := sanitizeREPLSession(session)
	sid := "p3y-repl-" + cleanSess
	if reset {
		_ = s.CloseInteractive(ctx, task, intent, sid)
		if code == "" {
			return &PyREPLResult{Session: cleanSess, Reset: true}, nil
		}
	}

	readOffset, err := s.ensurePyREPLSession(ctx, task, intent, sid)
	if err != nil && !reset {
		_ = s.CloseInteractive(ctx, task, intent, sid)
		readOffset, err = s.ensurePyREPLSession(ctx, task, intent, sid)
	}
	if err != nil {
		return nil, err
	}

	reqID := randomHex(6)
	payload, _ := json.Marshal(map[string]string{
		"id":       reqID,
		"code_b64": base64.StdEncoding.EncodeToString([]byte(code)),
	})
	if _, err := s.WriteInteractive(ctx, task, intent, sid, string(payload), "utf-8", true); err != nil {
		// Session died between start and write; restart cleanly once.
		_ = s.CloseInteractive(ctx, task, intent, sid)
		readOffset, err = s.ensurePyREPLSession(ctx, task, intent, sid)
		if err != nil {
			return nil, err
		}
		if _, err := s.WriteInteractive(ctx, task, intent, sid, string(payload), "utf-8", true); err != nil {
			return nil, fmt.Errorf("py_repl 写入失败: %w", err)
		}
	}

	marker := "__P3Y_REPL_DONE__:" + reqID + ":"
	var buf strings.Builder
	deadline := time.Now().Add(time.Duration(timeoutSec) * time.Second)
	for time.Now().Before(deadline) {
		waitMs := 500
		if rem := time.Until(deadline); rem < 500*time.Millisecond {
			waitMs = max(int(rem.Milliseconds()), 50)
		}
		rr, err := s.ReadInteractive(ctx, task, intent, sid, readOffset, waitMs)
		if err != nil {
			return nil, fmt.Errorf("py_repl 读取输出失败: %w", err)
		}
		readOffset = rr.Offset
		if rr.Output != "" {
			buf.WriteString(rr.Output)
			text := buf.String()
			if idx := strings.Index(text, marker); idx >= 0 {
				rest := text[idx+len(marker):]
				if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
					jsonLine := strings.TrimSpace(rest[:nl])
					var res PyREPLResult
					if uerr := json.Unmarshal([]byte(jsonLine), &res); uerr != nil {
						return nil, fmt.Errorf("py_repl 响应解析失败: %w", uerr)
					}
					res.Session = cleanSess
					res.Reset = reset
					return &res, nil
				}
			}
		}
		if !rr.Running {
			// Wait a tiny beat or exit with buffered error if process terminated.
			if buf.Len() > 0 && !strings.Contains(buf.String(), marker) {
				_ = s.CloseInteractive(ctx, task, intent, sid)
				return nil, fmt.Errorf("py_repl 会话意外退出：%s", excerpt([]byte(buf.String()), 800))
			}
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	_ = s.CloseInteractive(ctx, task, intent, sid)
	return nil, fmt.Errorf("py_repl 执行超时（%ds），已重置会话", timeoutSec)
}

func (s *Service) ensurePyREPLSession(ctx context.Context, task, intent int64, sid string) (int64, error) {
	sessions, err := s.ListInteractive(ctx, task, intent)
	if err == nil {
		for _, info := range sessions {
			if info.ID == sid && info.Running {
				// Drain to tail offset so previous output won't pollute next request.
				rr, rerr := s.ReadInteractive(ctx, task, intent, sid, 0, 50)
				if rerr == nil && rr.Running {
					return rr.Offset, nil
				}
				break
			}
		}
	}
	_ = s.CloseInteractive(ctx, task, intent, sid)
	b64Driver := base64.StdEncoding.EncodeToString([]byte(pyREPLServerScript))
	startCmd := fmt.Sprintf("python3 -u -c \"import base64; exec(base64.b64decode('%s').decode())\"", b64Driver)
	if _, err := s.StartInteractive(ctx, task, intent, startCmd, sid); err != nil {
		return 0, fmt.Errorf("启动 py_repl 失败: %w", err)
	}
	var offset int64
	var readyBuf strings.Builder
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		rr, err := s.ReadInteractive(ctx, task, intent, sid, offset, 300)
		if err != nil {
			return 0, err
		}
		offset = rr.Offset
		readyBuf.WriteString(rr.Output)
		if strings.Contains(readyBuf.String(), "__P3Y_REPL_READY__") {
			return offset, nil
		}
		if !rr.Running {
			return 0, fmt.Errorf("py_repl 启动即退出: %s", excerpt([]byte(readyBuf.String()), 500))
		}
	}
	return offset, nil
}

// PrepareForkWorkdirs creates isolated copy-on-write/hardlink workspace subdirectories inside
// /work/.forks/<forkID>/<branchSlug> initialized from snapshotID (falling back to current /work)
// so parallel Plateau Fork hypotheses never overwrite each other's scripts.
func (s *Service) PrepareForkWorkdirs(ctx context.Context, task, intent int64, forkID, snapshotID string, branchSlugs []string) (map[string]string, error) {
	if s == nil {
		return nil, fmt.Errorf("需要 CTF 沙箱上下文")
	}
	forkID = sanitizeREPLSession(forkID)
	dirs := make(map[string]string, len(branchSlugs))
	var b strings.Builder
	srcExpr := "/work"
	if strings.TrimSpace(snapshotID) != "" {
		snapSafe := filepath.Base(strings.TrimSpace(snapshotID))
		fmt.Fprintf(&b, "SRC=/work; [ -d %s ] && SRC=%s; ", quote("/snapshots/"+snapSafe), quote("/snapshots/"+snapSafe))
		srcExpr = `"$SRC"`
	}
	fmt.Fprintf(&b, "rm -rf %s && mkdir -p %s", quote("/work/.forks/"+forkID), quote("/work/.forks/"+forkID))
	for _, rawSlug := range branchSlugs {
		slug := sanitizeREPLSession(rawSlug)
		branchDir := "/work/.forks/" + forkID + "/" + slug
		dirs[rawSlug] = branchDir
		// Copy regular files & dirs excluding .inputs / .forks / .ghidra so each branch has an independent sandbox view.
		fmt.Fprintf(&b, " && mkdir -p %s && (cd %s && find . -maxdepth 4 -mindepth 1 ! -path './.inputs*' ! -path './.forks*' ! -path './.ghidra*' -exec cp -al --parents {} %s/ \\; 2>/dev/null || true)",
			quote(branchDir), srcExpr, quote(branchDir))
	}
	res, err := s.Execute(ctx, task, intent, b.String(), 30)
	if err != nil {
		return nil, fmt.Errorf("准备分叉工作区失败: %w", err)
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("准备分叉工作区退出码 %d: %s", res.ExitCode, res.StderrExcerpt)
	}
	return dirs, nil
}

// PromoteForkBranch promotes the winning branch workspace files back to /work and removes temporary fork dirs.
func (s *Service) PromoteForkBranch(ctx context.Context, task, intent int64, forkID, winnerSlug string) error {
	if s == nil {
		return fmt.Errorf("需要 CTF 沙箱上下文")
	}
	forkID = sanitizeREPLSession(forkID)
	winnerDir := "/work/.forks/" + forkID + "/" + sanitizeREPLSession(winnerSlug)
	cmd := fmt.Sprintf("if [ -d %s ]; then cp -af %s/. /work/ 2>/dev/null || true; fi && rm -rf %s",
		quote(winnerDir), quote(winnerDir), quote("/work/.forks/"+forkID))
	_, err := s.Execute(ctx, task, intent, cmd, 30)
	return err
}

func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
