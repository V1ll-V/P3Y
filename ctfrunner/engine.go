// Package ctfrunner manages isolated, credential-free CTF tool containers.
// Only this controller talks to Docker; the p3y application has no socket.
package ctfrunner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

type Engine struct {
	Client *http.Client
	Base   string
	Image  string
}

func DockerEngine(socket, image string) *Engine {
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	return &Engine{Client: &http.Client{Transport: tr}, Base: "http://docker/v1.47", Image: image}
}

func (e *Engine) call(ctx context.Context, method, p string, body io.Reader, contentType string) (*http.Response, error) {
	r, err := http.NewRequestWithContext(ctx, method, e.Base+p, body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	resp, err := e.Client.Do(r)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("Docker %s %s: %d %s", method, p, resp.StatusCode, b)
	}
	return resp, nil
}

func (e *Engine) json(ctx context.Context, method, p string, v, out any) error {
	var body io.Reader
	if v != nil {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	r, err := e.call(ctx, method, p, body, "application/json")
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if out != nil {
		return json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(out)
	}
	io.Copy(io.Discard, io.LimitReader(r.Body, 4096))
	return nil
}

type Container struct {
	ID     string
	Image  string
	State  struct{ Running bool }
	Config struct{ Labels map[string]string }
	Mounts []struct{ Name, Destination string }
}

// Java reads user.home rather than HOME. Keep Ghidra's JDK selection, settings,
// and logs on the writable task volume when the container root is read-only.
func toolEnvironment() []string {
	return []string{"HOME=/work", "XDG_CACHE_HOME=/work/.cache", "XDG_CONFIG_HOME=/work/.config", "JAVA_TOOL_OPTIONS=-Duser.home=/work", "PYTHONPYCACHEPREFIX=/tmp/pycache", "PWNLIB_NOTERM=1", "TERM=dumb"}
}

func mergeToolEnvironment(extra map[string]string) ([]string, string) {
	base := toolEnvironment()
	if len(extra) == 0 {
		return base, ""
	}
	keys := make([]string, 0, len(extra))
	for k := range extra {
		if strings.TrimSpace(k) != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return base, ""
	}
	h := sha256.New()
	merged := make([]string, 0, len(base)+len(keys))
	merged = append(merged, base...)
	for _, k := range keys {
		v := extra[k]
		merged = append(merged, k+"="+v)
		_, _ = h.Write([]byte(k + "=" + v + "\n"))
	}
	return merged, hex.EncodeToString(h.Sum(nil))[:16]
}

// SessionContainerOptions configures an isolated tool container for a session.
type SessionContainerOptions struct {
	Name          string
	Task          string
	InputHash     string
	VPNHash       string
	WorkVolume    string
	HostWorkDir   string
	HostInputsDir string
	ExtraEnv      map[string]string
}

func (e *Engine) Container(ctx context.Context, name string) (Container, error) {
	var c Container
	err := e.json(ctx, "GET", "/containers/"+url.PathEscape(name)+"/json", nil, &c)
	return c, err
}

func (e *Engine) Ensure(ctx context.Context, name, task, inputHash string) (string, error) {
	return e.EnsureSession(ctx, name, task, inputHash, "")
}

func (e *Engine) EnsureSession(ctx context.Context, name, task, inputHash, vpnHash string) (string, error) {
	return e.EnsureSessionWithOptions(ctx, SessionContainerOptions{
		Name:      name,
		Task:      task,
		InputHash: inputHash,
		VPNHash:   vpnHash,
	})
}

func (e *Engine) EnsureSessionWithOptions(ctx context.Context, opts SessionContainerOptions) (string, error) {
	name, task, inputHash, vpnHash := opts.Name, opts.Task, opts.InputHash, opts.VPNHash
	hostWork := strings.TrimSpace(opts.HostWorkDir)
	hostInputs := strings.TrimSpace(opts.HostInputsDir)
	workVol := strings.TrimSpace(opts.WorkVolume)
	if hostWork != "" {
		workVol = ""
	}
	envList, envHash := mergeToolEnvironment(opts.ExtraEnv)
	extraMounts, extraMountsHash := parseExtraReadOnlyMounts(os.Getenv("P3Y_BOX_EXTRA_RO_MOUNTS"))

	netMode, wgID, err := e.resolveSessionNetwork(ctx, task, vpnHash)
	if err != nil {
		return "", err
	}
	c, err := e.Container(ctx, name)
	if err == nil {
		if c.Config.Labels["p3y.box.managed"] != "true" || c.Config.Labels["p3y.box.task"] != task || c.Config.Labels["p3y.box.input"] != inputHash {
			return "", errors.New("CTF container ownership/input mismatch")
		}
		if c.Config.Labels["p3y.box.vpn"] != vpnHash ||
			c.Config.Labels["p3y.box.wg_id"] != wgID ||
			c.Config.Labels["p3y.box.work_mount"] != hostWork ||
			c.Config.Labels["p3y.box.work_vol"] != workVol ||
			c.Config.Labels["p3y.box.inputs_mount"] != hostInputs ||
			c.Config.Labels["p3y.box.env_hash"] != envHash ||
			c.Config.Labels["p3y.box.extra_mounts"] != extraMountsHash {
			if err = e.removeContainerOnly(ctx, name); err != nil {
				return "", err
			}
		} else {
			if !c.State.Running {
				if err = e.json(ctx, "POST", "/containers/"+c.ID+"/start", nil, nil); err != nil {
					return "", err
				}
			}
			return c.ID, nil
		}
	} else if !strings.Contains(err.Error(), ": 404 ") {
		return "", err
	}
	mounts := make([]map[string]any, 0, 2+len(extraMounts))
	if hostWork != "" {
		mounts = append(mounts, map[string]any{"Type": "bind", "Source": hostWork, "Target": "/work"})
	} else {
		volume := workVol
		volLabels := map[string]string{"p3y.box.managed": "true", "p3y.box.task": task}
		if volume != "" {
			volLabels["p3y.box.shared_work"] = "true"
		} else {
			volume = name + "-work"
		}
		if err = e.json(ctx, "POST", "/volumes/create", map[string]any{"Name": volume, "Labels": volLabels}, nil); err != nil {
			return "", err
		}
		mounts = append(mounts, map[string]any{"Type": "volume", "Source": volume, "Target": "/work"})
	}
	if hostInputs != "" {
		mounts = append(mounts, map[string]any{"Type": "bind", "Source": hostInputs, "Target": "/work/.inputs", "ReadOnly": true})
	}
	mounts = append(mounts, extraMounts...)
	labels := map[string]string{"p3y.box.managed": "true", "p3y.box.task": task, "p3y.box.input": inputHash}
	if vpnHash != "" {
		labels["p3y.box.vpn"] = vpnHash
		labels["p3y.box.wg_id"] = wgID
	}
	if hostWork != "" {
		labels["p3y.box.work_mount"] = hostWork
	}
	if workVol != "" {
		labels["p3y.box.work_vol"] = workVol
	}
	if hostInputs != "" {
		labels["p3y.box.inputs_mount"] = hostInputs
	}
	if envHash != "" {
		labels["p3y.box.env_hash"] = envHash
	}
	if extraMountsHash != "" {
		labels["p3y.box.extra_mounts"] = extraMountsHash
	}
	config := map[string]any{
		"Image": e.Image, "User": "1000:1000", "WorkingDir": "/work", "Entrypoint": []string{"sleep"}, "Cmd": []string{"infinity"},
		"Env":        envList,
		"Labels":     labels,
		"HostConfig": map[string]any{"ReadonlyRootfs": true, "Memory": int64(3 << 30), "NanoCpus": int64(2e9), "PidsLimit": int64(256), "CapDrop": []string{"ALL"}, "CapAdd": []string{"SYS_PTRACE"}, "SecurityOpt": []string{"no-new-privileges:true"}, "NetworkMode": netMode, "Tmpfs": map[string]string{"/tmp": "rw,nosuid,size=512m,mode=1777"}, "Mounts": mounts},
	}
	var result struct{ ID string }
	if err = e.json(ctx, "POST", "/containers/create?name="+url.QueryEscape(name), config, &result); err != nil {
		return "", err
	}
	if err = e.json(ctx, "POST", "/containers/"+result.ID+"/start", nil, nil); err != nil {
		return "", err
	}
	return result.ID, nil
}

type Result struct {
	Stdout     []byte    `json:"stdout"`
	Stderr     []byte    `json:"stderr"`
	ExitCode   int       `json:"exit_code"`
	Truncated  bool      `json:"truncated"`
	Error      string    `json:"error,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
}

func (e *Engine) Exec(ctx context.Context, id, command string) (result Result, err error) {
	return e.execWithOptions(ctx, id, "1000:1000", "/work", "/bin/bash", command, toolEnvironment(), true)
}

func (e *Engine) execRoot(ctx context.Context, id, command string) (result Result, err error) {
	return e.execWithOptions(ctx, id, "0:0", "/run/wg", "/bin/sh", command, nil, false)
}

func (e *Engine) execWithOptions(ctx context.Context, id, user, workdir, shell, command string, env []string, killOnErr bool) (result Result, err error) {
	result.StartedAt = time.Now().UTC()
	result.ExitCode = -1
	defer func() { result.FinishedAt = time.Now().UTC() }()
	var exec struct{ ID string }
	body := map[string]any{"AttachStdout": true, "AttachStderr": true, "Tty": false, "User": user, "WorkingDir": workdir, "Cmd": []string{shell, "-c", command}}
	if len(env) > 0 {
		body["Env"] = env
	}
	if err = e.json(ctx, "POST", "/containers/"+id+"/exec", body, &exec); err != nil {
		return
	}
	raw, _ := json.Marshal(map[string]bool{"Detach": false, "Tty": false})
	r, err := e.call(ctx, "POST", "/exec/"+exec.ID+"/start", bytes.NewReader(raw), "application/json")
	if err != nil {
		if killOnErr {
			e.kill(id)
		}
		return result, err
	}
	defer r.Body.Close()
	var stdout, stderr bytes.Buffer
	for {
		var header [8]byte
		_, err = io.ReadFull(r.Body, header[:])
		if errors.Is(err, io.EOF) {
			err = nil
			break
		}
		if err != nil {
			break
		}
		n := int64(binary.BigEndian.Uint32(header[4:]))
		if n < 0 || n > 16<<20 {
			err = errors.New("invalid Docker output frame")
			break
		}
		dst := &stdout
		if header[0] == 2 {
			dst = &stderr
		}
		remaining := int64(8<<20) - int64(dst.Len())
		keep := min(n, max(remaining, 0))
		if _, err = io.CopyN(dst, r.Body, keep); err != nil {
			break
		}
		if n > keep {
			result.Truncated = true
			if _, err = io.CopyN(io.Discard, r.Body, n-keep); err != nil {
				break
			}
		}
	}
	result.Stdout = stdout.Bytes()
	result.Stderr = stderr.Bytes()
	if err != nil || ctx.Err() != nil {
		if killOnErr {
			e.kill(id)
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return result, err
	}
	var state struct {
		ExitCode int
		Running  bool
	}
	if err = e.json(ctx, "GET", "/exec/"+exec.ID+"/json", nil, &state); err != nil {
		return
	}
	result.ExitCode = state.ExitCode
	return
}

func (e *Engine) kill(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = e.json(ctx, "POST", "/containers/"+id+"/kill", nil, nil)
}

func (e *Engine) Put(ctx context.Context, id string, r io.Reader) error {
	resp, err := e.call(ctx, "PUT", "/containers/"+id+"/archive?path=/work", r, "application/x-tar")
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}
func (e *Engine) Get(ctx context.Context, id string) (io.ReadCloser, error) {
	r, err := e.call(ctx, "GET", "/containers/"+id+"/archive?path=/work", nil, "")
	if err != nil {
		return nil, err
	}
	return r.Body, nil
}

func (e *Engine) Remove(ctx context.Context, name string) error {
	c, err := e.Container(ctx, name)
	if err != nil {
		if strings.Contains(err.Error(), ": 404 ") {
			return nil
		}
		return err
	}
	if c.Config.Labels["p3y.box.managed"] != "true" {
		return errors.New("refusing unmanaged container")
	}
	if err = e.json(ctx, "DELETE", "/containers/"+c.ID+"?force=1&v=1", nil, nil); err != nil {
		return err
	}
	for _, m := range c.Mounts {
		if m.Destination == "/work" && m.Name == name+"-work" {
			_ = e.json(ctx, "DELETE", "/volumes/"+url.PathEscape(m.Name), nil, nil)
		}
	}
	return nil
}

// parseExtraReadOnlyMounts parses P3Y_BOX_EXTRA_RO_MOUNTS entries of the form
// "<hostPath>:<containerTarget>" (comma/semicolon separated, supporting Windows
// drive prefixes like C:/data/case:/mnt/evidence). Only read-only mounts under
// /mnt/, /evidence/, or /opt/evidence/ are accepted so sandbox system paths stay protected.
func parseExtraReadOnlyMounts(raw string) ([]map[string]any, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, ""
	}
	var specs []string
	var mounts []map[string]any
	seenTarget := map[string]bool{}
	for _, entry := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ';' || r == '\n' }) {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		sep := strings.LastIndex(entry, ":")
		if sep <= 0 || sep >= len(entry)-1 {
			continue
		}
		src := strings.TrimSpace(entry[:sep])
		dst := path.Clean(strings.TrimSpace(entry[sep+1:]))
		if src == "" || strings.ContainsAny(src, "\x00\r\n") || !strings.HasPrefix(dst, "/") {
			continue
		}
		allowedTarget := strings.HasPrefix(dst, "/mnt/") || strings.HasPrefix(dst, "/evidence/") || strings.HasPrefix(dst, "/opt/evidence/")
		if !allowedTarget || seenTarget[dst] {
			continue
		}
		seenTarget[dst] = true
		specs = append(specs, src+"->"+dst)
		mounts = append(mounts, map[string]any{
			"Type":     "bind",
			"Source":   src,
			"Target":   dst,
			"ReadOnly": true,
		})
	}
	if len(mounts) == 0 {
		return nil, ""
	}
	sort.Strings(specs)
	sum := sha256.Sum256([]byte(strings.Join(specs, "\n")))
	return mounts, hex.EncodeToString(sum[:8])
}
