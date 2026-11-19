package ctfrunner

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Backend abstracts isolated container or local process-group execution for ctfrunner.Server.
type Backend interface {
	ImageName() string
	ImageID(ctx context.Context) (string, error)
	Ensure(ctx context.Context, name, task, inputHash string) (string, error)
	EnsureSessionWithOptions(ctx context.Context, opts SessionContainerOptions) (string, error)
	Container(ctx context.Context, id string) (Container, error)
	Exec(ctx context.Context, id, command string) (Result, error)
	Put(ctx context.Context, id string, r io.Reader) error
	Get(ctx context.Context, id string) (io.ReadCloser, error)
	Remove(ctx context.Context, name string) error
}

func (e *Engine) ImageName() string {
	if e == nil {
		return ""
	}
	return e.Image
}

func (e *Engine) ImageID(ctx context.Context) (string, error) {
	if e == nil {
		return "", errors.New("docker engine not configured")
	}
	var image struct{ ID string }
	if err := e.json(ctx, "GET", "/images/"+e.Image+"/json", nil, &image); err != nil {
		return "", err
	}
	return image.ID, nil
}

// LocalModeEnabled reports whether CTF sandbox execution should run in-process
// without Docker socket (single-container hosted benchmark / CLI mode).
func LocalModeEnabled() bool {
	return strings.TrimSpace(os.Getenv("P3Y_BOX_URL")) == "" && os.Getenv("P3Y_BOX_LOCAL") == "1"
}

const localRunnerURL = "http://local-p3y-box"
const localRunnerToken = "p3y-local-inproc-runner-token-0000"

type localSession struct {
	id          string
	task        string
	inputHash   string
	aliasDir    string
	hostWorkDir string
	env         map[string]string
}

// LocalBackend executes CTF commands inside isolated per-session directories on
// the current container without Docker-in-Docker.
type LocalBackend struct {
	WorkRoot   string
	ImageLabel string

	mu       sync.Mutex
	sessions map[string]*localSession
}

func NewLocalBackend(workRoot string) *LocalBackend {
	root := strings.TrimSpace(workRoot)
	if root == "" {
		root = filepath.Join(os.TempDir(), "p3y-w")
	}
	_ = os.MkdirAll(root, 0o700)
	return &LocalBackend{
		WorkRoot:   root,
		ImageLabel: "local-sandbox",
		sessions:   map[string]*localSession{},
	}
}

func (b *LocalBackend) ImageName() string {
	if b == nil || b.ImageLabel == "" {
		return "local-sandbox"
	}
	return b.ImageLabel
}

func (b *LocalBackend) ImageID(_ context.Context) (string, error) {
	return "local-sandbox", nil
}

func shortSessionSlug(name string) string {
	key := strings.TrimPrefix(strings.TrimSpace(name), "p3y-box-")
	if key == "" {
		key = "default"
	}
	if len(key) > 12 {
		key = key[:12]
	}
	return key
}

// WorkDirForKey returns the short local alias path used as /work for session key.
func (b *LocalBackend) WorkDirForKey(key string) string {
	return filepath.Join(b.WorkRoot, shortSessionSlug(key))
}

func (b *LocalBackend) Ensure(ctx context.Context, name, task, inputHash string) (string, error) {
	return b.EnsureSessionWithOptions(ctx, SessionContainerOptions{
		Name:      name,
		Task:      task,
		InputHash: inputHash,
	})
}

func (b *LocalBackend) EnsureSessionWithOptions(_ context.Context, opts SessionContainerOptions) (string, error) {
	if b == nil {
		return "", errors.New("local backend is nil")
	}
	if err := os.MkdirAll(b.WorkRoot, 0o700); err != nil {
		return "", err
	}
	aliasDir := b.WorkDirForKey(opts.Name)
	hostWork := strings.TrimSpace(opts.HostWorkDir)

	b.mu.Lock()
	defer b.mu.Unlock()

	if hostWork != "" {
		if err := os.MkdirAll(hostWork, 0o700); err != nil {
			return "", err
		}
		linkOK := false
		if fi, err := os.Lstat(aliasDir); err == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				if target, rerr := os.Readlink(aliasDir); rerr == nil && target == hostWork {
					linkOK = true
				}
			}
			if !linkOK {
				_ = removeLocalWorkDir(aliasDir)
			}
		}
		if !linkOK {
			if err := os.Symlink(hostWork, aliasDir); err != nil {
				return "", fmt.Errorf("create local work symlink: %w", err)
			}
		}
	} else {
		if fi, err := os.Lstat(aliasDir); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			_ = os.Remove(aliasDir)
		}
		if err := os.MkdirAll(aliasDir, 0o700); err != nil {
			return "", err
		}
	}

	b.sessions[opts.Name] = &localSession{
		id:          opts.Name,
		task:        opts.Task,
		inputHash:   opts.InputHash,
		aliasDir:    aliasDir,
		hostWorkDir: hostWork,
		env:         cloneStringMap(opts.ExtraEnv),
	}
	return opts.Name, nil
}

func (b *LocalBackend) Container(_ context.Context, id string) (Container, error) {
	b.mu.Lock()
	sess := b.sessions[id]
	b.mu.Unlock()
	if sess == nil {
		return Container{}, fmt.Errorf("session %s not found: 404 ", id)
	}
	c := Container{
		ID:    id,
		Image: b.ImageName(),
	}
	c.State.Running = true
	c.Config.Labels = map[string]string{
		"p3y.box.managed": "true",
		"p3y.box.task":    sess.task,
		"p3y.box.input":   sess.inputHash,
	}
	return c, nil
}

func (b *LocalBackend) sessionWorkDir(id string) (string, map[string]string, error) {
	b.mu.Lock()
	sess := b.sessions[id]
	b.mu.Unlock()
	if sess == nil {
		aliasDir := b.WorkDirForKey(id)
		if _, err := os.Stat(aliasDir); err == nil {
			return aliasDir, nil, nil
		}
		return "", nil, fmt.Errorf("local session %s not prepared", id)
	}
	return sess.aliasDir, sess.env, nil
}

type limitedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (w *limitedBuffer) Write(p []byte) (int, error) {
	if w.limit <= 0 {
		w.limit = 8 << 20
	}
	avail := w.limit - w.buf.Len()
	if avail > 0 {
		keep := min(len(p), avail)
		w.buf.Write(p[:keep])
	}
	if len(p) > avail {
		w.truncated = true
	}
	return len(p), nil
}

func (b *LocalBackend) Exec(ctx context.Context, id, command string) (result Result, err error) {
	result.StartedAt = time.Now().UTC()
	result.ExitCode = -1
	defer func() { result.FinishedAt = time.Now().UTC() }()

	workDir, extraEnv, err := b.sessionWorkDir(id)
	if err != nil {
		return result, err
	}
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return result, err
	}
	workSlash := filepath.ToSlash(workDir)
	rewritten := RewriteWorkPaths(command, workSlash)

	cmd := exec.Command("/bin/bash", "-c", rewritten)
	cmd.Dir = workDir
	cmd.Env = buildLocalToolEnv(workSlash, extraEnv)
	setProcessGroup(cmd)

	stdout := &limitedBuffer{limit: 8 << 20}
	stderr := &limitedBuffer{limit: 8 << 20}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err = cmd.Start(); err != nil {
		return result, err
	}

	waitDone := make(chan error, 1)
	go func() {
		waitDone <- cmd.Wait()
	}()

	select {
	case waitErr := <-waitDone:
		err = waitErr
	case <-ctx.Done():
		if cmd.Process != nil {
			killProcessGroup(cmd.Process.Pid)
			_ = cmd.Process.Kill()
		}
		<-waitDone
		err = ctx.Err()
	}

	result.Stdout = stdout.buf.Bytes()
	result.Stderr = stderr.buf.Bytes()
	result.Truncated = stdout.truncated || stderr.truncated

	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
			err = nil
		}
		return result, err
	}
	result.ExitCode = 0
	return result, nil
}

func (b *LocalBackend) Put(_ context.Context, id string, r io.Reader) error {
	workDir, _, err := b.sessionWorkDir(id)
	if err != nil {
		return err
	}
	tr := tar.NewReader(r)
	var readOnlyDirs []struct {
		path string
		mode os.FileMode
	}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		clean := path.Clean(strings.TrimSuffix(h.Name, "/"))
		if clean == "" || clean == "." || strings.HasPrefix(clean, "..") || path.IsAbs(clean) || strings.ContainsRune(clean, '\x00') {
			return errors.New("invalid archive path")
		}
		dst := filepath.Join(workDir, filepath.FromSlash(clean))
		// Ensure existing parent directories stay writable while syncing inputs.
		if parent := filepath.Dir(dst); parent != workDir {
			_ = os.MkdirAll(parent, 0o755)
			_ = os.Chmod(parent, 0o755)
		}
		if h.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(dst, 0o755); err != nil {
				return err
			}
			_ = os.Chmod(dst, 0o755)
			m := os.FileMode(h.Mode) & os.ModePerm
			if m != 0 {
				readOnlyDirs = append(readOnlyDirs, struct {
					path string
					mode os.FileMode
				}{path: dst, mode: m})
			}
			continue
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		_ = os.Remove(dst)
		mode := os.FileMode(h.Mode) & os.ModePerm
		if mode == 0 {
			mode = 0o600
		}
		f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		_, copyErr := io.CopyN(f, tr, h.Size)
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		_ = os.Chmod(dst, mode)
	}
	for i := len(readOnlyDirs) - 1; i >= 0; i-- {
		_ = os.Chmod(readOnlyDirs[i].path, readOnlyDirs[i].mode)
	}
	return nil
}

func (b *LocalBackend) Get(_ context.Context, id string) (io.ReadCloser, error) {
	workDir, _, err := b.sessionWorkDir(id)
	if err != nil {
		return nil, err
	}
	realRoot, err := filepath.EvalSymlinks(workDir)
	if err != nil {
		realRoot = workDir
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = filepath.WalkDir(realRoot, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil || p == realRoot {
			return nil
		}
		rel, rerr := filepath.Rel(realRoot, p)
		if rerr != nil {
			return nil
		}
		slash := filepath.ToSlash(rel)
		if slash == ".inputs" || strings.HasPrefix(slash, ".inputs/") ||
			slash == ".snapshots" || strings.HasPrefix(slash, ".snapshots/") ||
			slash == ".cache" || strings.HasPrefix(slash, ".cache/") ||
			slash == ".ghidra" || strings.HasPrefix(slash, ".ghidra/") ||
			slash == ".jobs" || strings.HasPrefix(slash, ".jobs/") ||
			slash == ".interactive" || strings.HasPrefix(slash, ".interactive/") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		hdr, herr := tar.FileInfoHeader(info, "")
		if herr != nil {
			return nil
		}
		hdr.Name = "work/" + slash
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			f, ferr := os.Open(p)
			if ferr != nil {
				return nil
			}
			_, _ = io.CopyN(tw, f, info.Size())
			_ = f.Close()
		}
		return nil
	})
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return io.NopCloser(&buf), nil
}

func (b *LocalBackend) Remove(_ context.Context, name string) error {
	b.mu.Lock()
	sess := b.sessions[name]
	delete(b.sessions, name)
	b.mu.Unlock()

	aliasDir := b.WorkDirForKey(name)
	if sess != nil && sess.aliasDir != "" {
		aliasDir = sess.aliasDir
	}
	fi, err := os.Lstat(aliasDir)
	if err != nil {
		return nil
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return os.Remove(aliasDir)
	}
	return removeLocalWorkDir(aliasDir)
}

func removeLocalWorkDir(dir string) error {
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			_ = os.Chmod(p, 0o700)
		} else {
			_ = os.Chmod(p, 0o600)
		}
		return nil
	})
	return os.RemoveAll(dir)
}

func isPathWordChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'
}

func isPathPrefixChar(c byte) bool {
	return isPathWordChar(c) || c == '/'
}

// RewriteWorkPaths translates standalone /work path references (e.g. /work,
// /work/exp.py, "/work/.inputs/...") into workAlias without altering URLs,
// parent paths (/app/work), or names like /workspace.
func RewriteWorkPaths(input, workAlias string) string {
	workAlias = strings.TrimRight(strings.TrimSpace(workAlias), "/")
	if workAlias == "" || workAlias == "/work" || !strings.Contains(input, "/work") {
		return input
	}
	var out strings.Builder
	const needle = "/work"
	i := 0
	for i < len(input) {
		idx := strings.Index(input[i:], needle)
		if idx < 0 {
			out.WriteString(input[i:])
			break
		}
		pos := i + idx
		end := pos + len(needle)
		prevOK := pos == 0 || !isPathPrefixChar(input[pos-1])
		nextOK := end == len(input) || input[end] == '/' || !isPathWordChar(input[end])
		if prevOK && nextOK {
			out.WriteString(input[i:pos])
			out.WriteString(workAlias)
			i = end
			continue
		}
		out.WriteString(input[i : pos+1])
		i = pos + 1
	}
	return out.String()
}

func buildLocalToolEnv(workDir string, extra map[string]string) []string {
	blockedExact := map[string]bool{
		"P3Y_PG_DSN":        true,
		"P3Y_BOX_TOKEN":     true,
		"BENCHMARK_TOKEN":   true,
		"ADMIN_PASSWORD":    true,
		"OPENAI_API_KEY":    true,
		"ANTHROPIC_API_KEY": true,
		"DEEPSEEK_API_KEY":  true,
		"KIMI_API_KEY":      true,
		"GLM_API_KEY":       true,
	}
	envMap := map[string]string{}
	for _, entry := range os.Environ() {
		k, v, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		uk := strings.ToUpper(strings.TrimSpace(k))
		if blockedExact[uk] || strings.HasSuffix(uk, "_API_KEY") || strings.HasSuffix(uk, "_API_KEYS") {
			continue
		}
		envMap[k] = v
	}
	envMap["HOME"] = workDir
	envMap["PWD"] = workDir
	envMap["P3Y_WORK_DIR"] = workDir
	envMap["XDG_CACHE_HOME"] = workDir + "/.cache"
	envMap["XDG_CONFIG_HOME"] = workDir + "/.config"
	envMap["JAVA_TOOL_OPTIONS"] = "-Duser.home=" + workDir
	envMap["PYTHONPYCACHEPREFIX"] = "/tmp/pycache"
	envMap["PWNLIB_NOTERM"] = "1"
	envMap["TERM"] = "dumb"
	for k, v := range extra {
		if strings.TrimSpace(k) != "" {
			envMap[k] = v
		}
	}
	out := make([]string, 0, len(envMap))
	for k, v := range envMap {
		out = append(out, k+"="+v)
	}
	return out
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

type handlerTransport struct {
	handler http.Handler
}

func (t handlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	t.handler.ServeHTTP(rec, req)
	res := rec.Result()
	res.Request = req
	return res, nil
}

// NewLocalClient constructs an in-process ctfrunner Client backed by LocalBackend
// without requiring Docker or TCP ports.
func NewLocalClient(workRoot, stateDir string) (*Client, *LocalBackend) {
	if strings.TrimSpace(stateDir) == "" {
		stateDir = filepath.Join(os.TempDir(), "p3y-local-state")
	}
	_ = os.MkdirAll(stateDir, 0o700)
	lb := NewLocalBackend(workRoot)
	srv := &Server{
		Backend:  lb,
		Token:    localRunnerToken,
		StateDir: stateDir,
	}
	return &Client{
		URL:           localRunnerURL,
		Token:         localRunnerToken,
		HTTP:          &http.Client{Transport: handlerTransport{handler: srv.Handler()}},
		localWorkRoot: lb.WorkRoot,
	}, lb
}

var (
	defaultLocalOnce   sync.Once
	defaultLocalClient *Client
	defaultLocalBack   *LocalBackend
)

// DefaultLocalClient returns a process-wide shared in-memory local ctfrunner client.
func DefaultLocalClient() *Client {
	defaultLocalOnce.Do(func() {
		defaultLocalClient, defaultLocalBack = NewLocalClient("", "")
	})
	return defaultLocalClient
}

// IsLocalClient reports whether c targets an in-process LocalBackend.
func IsLocalClient(c *Client) bool {
	return c != nil && strings.HasPrefix(strings.TrimSpace(c.URL), localRunnerURL)
}

// LocalWorkAlias resolves the local directory alias mapped to /work for session key.
func LocalWorkAlias(c *Client, key string) string {
	if !IsLocalClient(c) {
		return "/work"
	}
	root := strings.TrimSpace(c.localWorkRoot)
	if root == "" && defaultLocalBack != nil {
		root = defaultLocalBack.WorkRoot
	}
	if root == "" {
		root = filepath.Join(os.TempDir(), "p3y-w")
	}
	return filepath.ToSlash(filepath.Join(root, shortSessionSlug(key)))
}
