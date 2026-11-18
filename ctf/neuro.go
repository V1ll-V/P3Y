package ctf

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"strings"
)

// HTTPFuzzDiffSpec defines parameters for batch HTTP fuzzing with baseline diff clustering.
type HTTPFuzzDiffSpec struct {
	URL             string            `json:"url"`
	Method          string            `json:"method,omitempty"`
	Param           string            `json:"param,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	BodyTemplate    string            `json:"body_template,omitempty"`
	Cookies         map[string]string `json:"cookies,omitempty"`
	Payloads        []string          `json:"payloads"`
	BaselinePayload string            `json:"baseline_payload,omitempty"`
	TimeoutSeconds  int               `json:"timeout_seconds,omitempty"`
	MaxWorkers      int               `json:"max_workers,omitempty"`
	FollowRedirects bool              `json:"follow_redirects,omitempty"`
}

// BuildHTTPFuzzDiffCommand compiles a deterministic sandbox Python command that runs
// baseline + payload batch requests in parallel and returns clustered structural diffs.
func BuildHTTPFuzzDiffCommand(spec HTTPFuzzDiffSpec) (string, int, error) {
	u, err := url.Parse(strings.TrimSpace(spec.URL))
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", 0, fmt.Errorf("url 必须是有效的 http/https 地址")
	}
	if len(spec.Payloads) == 0 {
		return "", 0, fmt.Errorf("payloads 不能为空")
	}
	if len(spec.Payloads) > 64 {
		return "", 0, fmt.Errorf("单次 http_fuzz_diff 最多支持 64 个 payloads（当前 %d）", len(spec.Payloads))
	}
	method := strings.ToUpper(strings.TrimSpace(spec.Method))
	if method == "" {
		if strings.TrimSpace(spec.BodyTemplate) != "" {
			method = "POST"
		} else {
			method = "GET"
		}
	}
	switch method {
	case "GET", "POST", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS":
	default:
		return "", 0, fmt.Errorf("不支持的 HTTP 方法 %q", method)
	}
	hasMarker := strings.Contains(spec.URL, "{FUZZ}") || strings.Contains(spec.BodyTemplate, "{FUZZ}")
	for _, v := range spec.Headers {
		if strings.Contains(v, "{FUZZ}") {
			hasMarker = true
			break
		}
	}
	if !hasMarker && strings.TrimSpace(spec.Param) == "" {
		return "", 0, fmt.Errorf("必须在 url/body_template/headers 中包含 {FUZZ} 占位符或指定 param")
	}
	if spec.TimeoutSeconds <= 0 {
		spec.TimeoutSeconds = 10
	}
	if spec.TimeoutSeconds > 60 {
		spec.TimeoutSeconds = 60
	}
	if spec.MaxWorkers <= 0 {
		spec.MaxWorkers = 6
	}
	if spec.MaxWorkers > 16 {
		spec.MaxWorkers = 16
	}
	if spec.BaselinePayload == "" {
		spec.BaselinePayload = "p3y_baseline_probe_9182"
	}
	spec.Method = method
	cfgBytes, err := json.Marshal(spec)
	if err != nil {
		return "", 0, err
	}
	script := `import base64, concurrent.futures, difflib, hashlib, json, os, re, ssl, sys, time, urllib.error, urllib.parse, urllib.request

cfg = json.loads(base64.b64decode(sys.argv[1]).decode('utf-8'))
ssl_ctx = None
ca_file = os.environ.get('SSL_CERT_FILE') or os.environ.get('REQUESTS_CA_BUNDLE')
if ca_file and os.path.exists(ca_file):
    ssl_ctx = ssl.create_default_context(cafile=ca_file)
elif os.environ.get('HTTPS_PROXY') or os.environ.get('HTTP_PROXY'):
    ssl_ctx = ssl.create_default_context()

ERR_PATTERNS = re.compile(r'(sql syntax|mysql|sqlite|postgres|syntaxerror|traceback|warning:|fatal error|exception|stack trace|flag\{|ctf\{)', re.I)

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def build_req(payload):
    url = cfg['url']
    body = cfg.get('body_template') or ''
    headers = dict(cfg.get('headers') or {})
    param = (cfg.get('param') or '').strip()
    enc = urllib.parse.quote(payload, safe='')
    if '{FUZZ}' in url:
        url = url.replace('{FUZZ}', enc)
    elif param and cfg['method'] in ('GET', 'HEAD', 'DELETE') and '{FUZZ}' not in body:
        p = urllib.parse.urlsplit(url)
        q = urllib.parse.parse_qs(p.query, keep_blank_values=True)
        q[param] = [payload]
        url = urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, urllib.parse.urlencode(q, doseq=True), p.fragment))
    if '{FUZZ}' in body:
        body = body.replace('{FUZZ}', payload)
    elif param and cfg['method'] in ('POST', 'PUT', 'PATCH') and not body:
        body = urllib.parse.urlencode({param: payload})
        if not any(k.lower() == 'content-type' for k in headers):
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
    for k, v in list(headers.items()):
        if '{FUZZ}' in v:
            headers[k] = v.replace('{FUZZ}', payload)
    if cfg.get('cookies'):
        cookie_hdr = '; '.join(f"{k}={v}" for k, v in cfg['cookies'].items())
        headers['Cookie'] = (headers.get('Cookie') + '; ' if headers.get('Cookie') else '') + cookie_hdr
    data = body.encode('utf-8') if body and cfg['method'] != 'HEAD' else None
    return urllib.request.Request(url, data=data, headers=headers, method=cfg['method'])

def send_one(payload):
    t0 = time.monotonic()
    req = build_req(payload)
    handlers = [] if cfg.get('follow_redirects') else [NoRedirect()]
    if ssl_ctx is not None:
        handlers.append(urllib.request.HTTPSHandler(context=ssl_ctx))
    opener = urllib.request.build_opener(*handlers)
    status = 0
    raw = b''
    resp_headers = {}
    err_str = ''
    try:
        with opener.open(req, timeout=cfg['timeout_seconds']) as r:
            status = r.getcode()
            raw = r.read(262144)
            resp_headers = {k.lower(): v for k, v in r.headers.items()}
    except urllib.error.HTTPError as e:
        status = e.code
        raw = e.read(262144)
        resp_headers = {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
    except Exception as e:
        err_str = str(e)
    elapsed_ms = int((time.monotonic() - t0) * 1000)
    text = raw.decode('utf-8', errors='replace')
    sha = hashlib.sha256(raw).hexdigest()[:12]
    hits = sorted(set(m.group(0)[:40] for m in ERR_PATTERNS.finditer(text)))[:6]
    title_m = re.search(r'<title>(.*?)</title>', text, re.I | re.S)
    title = re.sub(r'\s+', ' ', title_m.group(1)).strip()[:80] if title_m else ''
    return {
        'payload': payload,
        'status': status,
        'length': len(raw),
        'sha256': sha,
        'elapsed_ms': elapsed_ms,
        'location': resp_headers.get('location', ''),
        'title': title,
        'hints': hits,
        'error': err_str,
        'text': text,
    }

base = send_one(cfg['baseline_payload'])
base_lines = base['text'].splitlines()
with concurrent.futures.ThreadPoolExecutor(max_workers=cfg['max_workers']) as pool:
    results = list(pool.map(send_one, cfg['payloads']))

clusters = {}
anomalies = []
for r in results:
    sig = (r['status'], r['length'], r['sha256'], r['error'])
    clusters.setdefault(sig, []).append(r['payload'])
    time_anom = base['elapsed_ms'] > 0 and r['elapsed_ms'] >= max(1500, base['elapsed_ms'] * 2.5)
    interesting = (r['status'] != base['status'] or r['sha256'] != base['sha256'] or r['error'] or r['hints'] or time_anom)
    if interesting:
        diff_lines = list(difflib.unified_diff(base_lines, r['text'].splitlines(), fromfile='baseline', tofile='probe', lineterm='', n=1))
        anomalies.append({
            'payload': r['payload'],
            'status': r['status'],
            'length_delta': r['length'] - base['length'],
            'elapsed_ms': r['elapsed_ms'],
            'time_anomaly': time_anom,
            'location': r['location'],
            'title': r['title'],
            'hints': r['hints'],
            'error': r['error'],
            'diff_excerpt': '\n'.join(diff_lines[:24]),
        })

cluster_summary = [
    {'status': k[0], 'length': k[1], 'sha256': k[2], 'error': k[3], 'count': len(ps), 'sample_payloads': ps[:4]}
    for k, ps in sorted(clusters.items(), key=lambda kv: -len(kv[1]))
]
out = {
    'baseline': {k: base[k] for k in ('payload', 'status', 'length', 'sha256', 'elapsed_ms', 'location', 'title', 'hints', 'error')},
    'total_probes': len(results),
    'clusters': cluster_summary[:10],
    'anomalies': anomalies[:15],
}
print(json.dumps(out, ensure_ascii=False))
`
	b64Script := base64.StdEncoding.EncodeToString([]byte(script))
	b64Cfg := base64.StdEncoding.EncodeToString(cfgBytes)
	cmd := fmt.Sprintf("python3 -c \"import base64; exec(base64.b64decode('%s').decode())\" %s", b64Script, b64Cfg)
	totalTimeout := min(max(spec.TimeoutSeconds*3+10, 30), 180)
	return cmd, totalTimeout, nil
}

// DiffLocalRemoteSpec defines a deterministic comparison run between a local target and a remote target.
type DiffLocalRemoteSpec struct {
	ScriptPath     string            `json:"script_path,omitempty"`
	LocalArgs      []string          `json:"local_args,omitempty"`
	RemoteArgs     []string          `json:"remote_args,omitempty"`
	LocalCmd       string            `json:"local_cmd,omitempty"`
	RemoteCmd      string            `json:"remote_cmd,omitempty"`
	LocalEnv       map[string]string `json:"local_env,omitempty"`
	RemoteEnv      map[string]string `json:"remote_env,omitempty"`
	StdinText      string            `json:"stdin_text,omitempty"`
	TimeoutSeconds int               `json:"timeout_seconds,omitempty"`
}

// BuildDiffLocalRemoteCommand compiles a sandbox Python command that runs both local and remote
// variants, aligns stdout/stderr/exit codes/leaked addresses, and returns a compact unified diff.
func BuildDiffLocalRemoteCommand(spec DiffLocalRemoteSpec) (string, int, error) {
	scriptPath := strings.TrimSpace(spec.ScriptPath)
	localCmd := strings.TrimSpace(spec.LocalCmd)
	remoteCmd := strings.TrimSpace(spec.RemoteCmd)
	if scriptPath == "" && (localCmd == "" || remoteCmd == "") {
		return "", 0, fmt.Errorf("请提供 script_path，或同时提供 local_cmd 与 remote_cmd")
	}
	if scriptPath != "" {
		clean := path.Clean(scriptPath)
		if !path.IsAbs(clean) {
			clean = path.Join("/work", clean)
		}
		if clean != "/work" && !strings.HasPrefix(clean, "/work/") {
			return "", 0, fmt.Errorf("script_path 必须位于 /work 内")
		}
		spec.ScriptPath = clean
	}
	if spec.TimeoutSeconds <= 0 {
		spec.TimeoutSeconds = 15
	}
	if spec.TimeoutSeconds > 60 {
		spec.TimeoutSeconds = 60
	}
	cfgBytes, err := json.Marshal(spec)
	if err != nil {
		return "", 0, err
	}
	script := `import base64, difflib, json, os, re, shlex, subprocess, sys, time

cfg = json.loads(base64.b64decode(sys.argv[1]).decode('utf-8'))
ADDR_RE = re.compile(r'0x[0-9a-fA-F]{4,16}')
DIAG_PATTERNS = [
    ('eof_or_pipe', re.compile(r'(EOFError|BrokenPipeError|ConnectionResetError)', re.I)),
    ('timeout', re.compile(r'(TimeoutExpired|timed out)', re.I)),
    ('segfault', re.compile(r'(Segmentation fault|SIGSEGV|core dumped)', re.I)),
    ('stack_canary', re.compile(r'stack smashing detected', re.I)),
    ('conn_refused', re.compile(r'ConnectionRefusedError|Connection refused', re.I)),
]

def run_side(mode):
    env = dict(os.environ)
    extra_env = cfg.get('local_env' if mode == 'local' else 'remote_env') or {}
    env.update({str(k): str(v) for k, v in extra_env.items()})
    env.setdefault('P3Y_DIFF_MODE', mode)
    sp = cfg.get('script_path') or ''
    if sp:
        args = cfg.get('local_args' if mode == 'local' else 'remote_args') or []
        cmd_list = ['python3', sp] + [str(a) for a in args]
        use_shell = False
    else:
        cmd_list = cfg['local_cmd' if mode == 'local' else 'remote_cmd']
        use_shell = True
    t0 = time.monotonic()
    stdin_data = cfg.get('stdin_text') or None
    try:
        p = subprocess.run(
            cmd_list, shell=use_shell, input=stdin_data, text=True,
            capture_output=True, timeout=cfg['timeout_seconds'], env=env, cwd='/work'
        )
        rc = p.returncode
        out, err = p.stdout or '', p.stderr or ''
        timed_out = False
    except subprocess.TimeoutExpired as e:
        rc = -1
        out = (e.stdout.decode('utf-8', 'replace') if isinstance(e.stdout, bytes) else (e.stdout or ''))
        err = (e.stderr.decode('utf-8', 'replace') if isinstance(e.stderr, bytes) else (e.stderr or '')) + f"\nTimeoutExpired({cfg['timeout_seconds']}s)"
        timed_out = True
    elapsed = int((time.monotonic() - t0) * 1000)
    combined = out + '\n' + err
    addrs = list(dict.fromkeys(ADDR_RE.findall(combined)))[:12]
    signals = [name for name, pat in DIAG_PATTERNS if pat.search(combined)]
    return {
        'exit_code': rc,
        'timed_out': timed_out,
        'elapsed_ms': elapsed,
        'stdout_tail': '\n'.join(out.splitlines()[-40:])[-4000:],
        'stderr_tail': '\n'.join(err.splitlines()[-30:])[-2500:],
        'hex_addresses': addrs,
        'signals': signals,
        'lines': (out + ('\n[STDERR]\n' + err if err.strip() else '')).splitlines(),
    }

loc = run_side('local')
rem = run_side('remote')
udiff = list(difflib.unified_diff(loc['lines'], rem['lines'], fromfile='local', tofile='remote', lineterm='', n=2))

hints = []
if loc['exit_code'] == 0 and rem['exit_code'] != 0:
    hints.append('本地 exit=0 但远端失败，优先核查远端 libc/栈对齐(16-byte MOVAPS)/环境变量或缓冲差异。')
if 'eof_or_pipe' in rem['signals'] and 'eof_or_pipe' not in loc['signals']:
    hints.append('远端出现 EOFError/BrokenPipe，可能原因：1) 攻击载荷在远端提前崩溃(栈偏移/gadget 差异)；2) 远端行缓冲/PoW/RTT 延迟需加 sendafter/sleep。')
if 'timeout' in rem['signals'] and 'timeout' not in loc['signals']:
    hints.append('远端超时而本地未超时，检查提示符匹配字符串(recvuntil)或交互是否已进 shell 等待进一步 stdin。')
if loc['hex_addresses'] and not rem['hex_addresses']:
    hints.append('本地成功泄露 hex 地址但远端未泄露，核对远端接收截断/偏移或泄露触发路径。')

loc.pop('lines', None)
rem.pop('lines', None)
print(json.dumps({
    'local': loc,
    'remote': rem,
    'unified_diff': '\n'.join(udiff[:80]),
    'diagnosis_hints': hints,
}, ensure_ascii=False))
`
	b64Script := base64.StdEncoding.EncodeToString([]byte(script))
	b64Cfg := base64.StdEncoding.EncodeToString(cfgBytes)
	cmd := fmt.Sprintf("python3 -c \"import base64; exec(base64.b64decode('%s').decode())\" %s", b64Script, b64Cfg)
	totalTimeout := min(max(spec.TimeoutSeconds*2+10, 25), 140)
	return cmd, totalTimeout, nil
}

// HTTPRaceProbeSpec configures a synchronized barrier burst test for Web race conditions / TOCTOU.
type HTTPRaceProbeSpec struct {
	URL            string            `json:"url"`
	Method         string            `json:"method,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"`
	Body           string            `json:"body,omitempty"`
	Cookies        map[string]string `json:"cookies,omitempty"`
	PreURL         string            `json:"pre_url,omitempty"`
	PreMethod      string            `json:"pre_method,omitempty"`
	PreBody        string            `json:"pre_body,omitempty"`
	Concurrency    int               `json:"concurrency,omitempty"`
	TimeoutSeconds int               `json:"timeout_seconds,omitempty"`
}

// BuildHTTPRaceProbeCommand builds a sandbox Python script that pre-connects N worker
// sockets, aligns them on a threading.Barrier, and fires simultaneous HTTP requests
// to detect race condition / TOCTOU anomalies.
func BuildHTTPRaceProbeCommand(spec HTTPRaceProbeSpec) (string, int, error) {
	u, err := url.Parse(strings.TrimSpace(spec.URL))
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", 0, fmt.Errorf("url 必须是有效的 http/https 地址")
	}
	if strings.TrimSpace(spec.PreURL) != "" {
		pu, perr := url.Parse(strings.TrimSpace(spec.PreURL))
		if perr != nil || pu.Hostname() == "" || (pu.Scheme != "http" && pu.Scheme != "https") {
			return "", 0, fmt.Errorf("pre_url 必须是有效的 http/https 地址")
		}
	}
	method := strings.ToUpper(strings.TrimSpace(spec.Method))
	if method == "" {
		if spec.Body != "" {
			method = "POST"
		} else {
			method = "GET"
		}
	}
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD":
	default:
		return "", 0, fmt.Errorf("不支持的 HTTP 方法 %q", method)
	}
	spec.Method = method
	if spec.Concurrency <= 0 {
		spec.Concurrency = 20
	}
	if spec.Concurrency < 2 {
		spec.Concurrency = 2
	}
	if spec.Concurrency > 40 {
		spec.Concurrency = 40
	}
	if spec.TimeoutSeconds <= 0 {
		spec.TimeoutSeconds = 10
	}
	if spec.TimeoutSeconds > 30 {
		spec.TimeoutSeconds = 30
	}
	cfgBytes, err := json.Marshal(spec)
	if err != nil {
		return "", 0, err
	}
	script := `import base64, hashlib, http.client, json, os, ssl, sys, threading, time, urllib.parse, urllib.request

cfg = json.loads(base64.b64decode(sys.argv[1]).decode('utf-8'))
ssl_ctx = None
ca_file = os.environ.get('SSL_CERT_FILE') or os.environ.get('REQUESTS_CA_BUNDLE')
if ca_file and os.path.exists(ca_file):
    ssl_ctx = ssl.create_default_context(cafile=ca_file)
elif os.environ.get('HTTPS_PROXY') or os.environ.get('HTTP_PROXY'):
    ssl_ctx = ssl.create_default_context()

def build_headers():
    h = dict(cfg.get('headers') or {})
    if cfg.get('cookies'):
        ck = '; '.join(f"{k}={v}" for k, v in cfg['cookies'].items())
        h['Cookie'] = (h.get('Cookie') + '; ' if h.get('Cookie') else '') + ck
    return h

if cfg.get('pre_url'):
    pm = (cfg.get('pre_method') or ('POST' if cfg.get('pre_body') else 'GET')).upper()
    pdata = (cfg.get('pre_body') or '').encode('utf-8') if cfg.get('pre_body') else None
    preq = urllib.request.Request(cfg['pre_url'], data=pdata, headers=build_headers(), method=pm)
    try:
        with urllib.request.urlopen(preq, timeout=cfg['timeout_seconds'], context=ssl_ctx) as _:
            pass
    except Exception:
        pass

u = urllib.parse.urlsplit(cfg['url'])
path = u.path or '/'
if u.query:
    path += '?' + u.query
proxy_url = os.environ.get('HTTPS_PROXY' if u.scheme == 'https' else 'HTTP_PROXY') or os.environ.get('https_proxy' if u.scheme == 'https' else 'http_proxy')
n = cfg['concurrency']
barrier = threading.Barrier(n, timeout=cfg['timeout_seconds'])
headers = build_headers()
body_bytes = (cfg.get('body') or '').encode('utf-8') if cfg.get('body') else None
if body_bytes is not None and not any(k.lower() == 'content-type' for k in headers):
    headers['Content-Type'] = 'application/x-www-form-urlencoded'

results = [None] * n

def make_conn():
    host = u.hostname
    port = u.port or (443 if u.scheme == 'https' else 80)
    if proxy_url:
        pu = urllib.parse.urlsplit(proxy_url)
        ph, pp = pu.hostname, pu.port or 80
        if u.scheme == 'https':
            c = http.client.HTTPSConnection(ph, pp, timeout=cfg['timeout_seconds'], context=ssl_ctx)
            c.set_tunnel(host, port)
            return c, path
        c = http.client.HTTPConnection(ph, pp, timeout=cfg['timeout_seconds'])
        return c, cfg['url']
    if u.scheme == 'https':
        return http.client.HTTPSConnection(host, port, timeout=cfg['timeout_seconds'], context=ssl_ctx), path
    return http.client.HTTPConnection(host, port, timeout=cfg['timeout_seconds']), path

def worker(idx):
    conn = None
    status = 0
    raw = b''
    err_str = ''
    t0 = 0.0
    try:
        conn, req_target = make_conn()
        conn.connect()
        barrier.wait()
        t0 = time.monotonic()
        conn.request(cfg['method'], req_target, body=body_bytes, headers=headers)
        resp = conn.getresponse()
        status = resp.status
        raw = resp.read(65536)
    except Exception as e:
        err_str = str(e)
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
    elapsed_ms = int((time.monotonic() - t0) * 1000) if t0 else 0
    sha = hashlib.sha256(raw).hexdigest()[:12]
    results[idx] = {
        'status': status,
        'length': len(raw),
        'sha256': sha,
        'elapsed_ms': elapsed_ms,
        'error': err_str,
        'excerpt': raw.decode('utf-8', 'replace')[:320],
    }

threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
for t in threads:
    t.start()
for t in threads:
    t.join()

clusters = {}
elapsed_list = []
for r in results:
    sig = (r['status'], r['length'], r['sha256'], r['error'])
    if sig not in clusters:
        clusters[sig] = {'status': r['status'], 'length': r['length'], 'sha256': r['sha256'], 'error': r['error'], 'count': 0, 'excerpt': r['excerpt']}
    clusters[sig]['count'] += 1
    if r['elapsed_ms'] > 0:
        elapsed_list.append(r['elapsed_ms'])

cluster_list = sorted(clusters.values(), key=lambda c: -c['count'])
non_err = [c for c in cluster_list if not c['error'] and c['status'] > 0]
out = {
    'concurrency': n,
    'distinct_clusters': len(cluster_list),
    'race_anomaly': len(non_err) > 1,
    'elapsed_min_ms': min(elapsed_list) if elapsed_list else 0,
    'elapsed_max_ms': max(elapsed_list) if elapsed_list else 0,
    'clusters': cluster_list[:8],
}
print(json.dumps(out, ensure_ascii=False))
`
	b64Script := base64.StdEncoding.EncodeToString([]byte(script))
	b64Cfg := base64.StdEncoding.EncodeToString(cfgBytes)
	cmd := fmt.Sprintf("python3 -c \"import base64; exec(base64.b64decode('%s').decode())\" %s", b64Script, b64Cfg)
	totalTimeout := min(max(spec.TimeoutSeconds*2+10, 25), 90)
	return cmd, totalTimeout, nil
}
