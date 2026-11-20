package ctf

import (
	"archive/zip"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"p3y/artifacts"
	"p3y/ctfrunner"
	"p3y/db"
)

func buildMinimalELF64Header(machine uint16, elfType uint16) []byte {
	buf := make([]byte, 64)
	copy(buf[:4], []byte{0x7f, 'E', 'L', 'F'})
	buf[4] = 2 // 64-bit
	buf[5] = 1 // little-endian
	buf[6] = 1 // EI_VERSION
	binary.LittleEndian.PutUint16(buf[16:18], elfType)
	binary.LittleEndian.PutUint16(buf[18:20], machine)
	binary.LittleEndian.PutUint32(buf[20:24], 1)
	binary.LittleEndian.PutUint16(buf[52:54], 64)
	return buf
}

func TestRunPrecheckExtractsELFZipTargetsAndTips(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("test database required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()

	if err := pg.SeedDefaultTips(t.Context()); err != nil {
		t.Fatal(err)
	}
	task, err := pg.CreateTaskWithOptions("precheck-demo", "Connect nc 10.20.30.40 9999 and leak libc via https://ctf.example.com/hint", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "auto"})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)

	root := t.TempDir()
	store := artifacts.Store{Root: root}
	// Add a minimal ELF64 amd64 non-PIE binary header + a zip archive.
	elfBytes := buildMinimalELF64Header(62 /* EM_X86_64 */, 2 /* ET_EXEC */)
	if _, err := store.Add("task", fmt.Sprint(task.ID), "pwn_chall", "binary", strings.NewReader(string(elfBytes))); err != nil {
		t.Fatal(err)
	}
	zipPath := filepath.Join(t.TempDir(), "bundle.zip")
	if f, err := os.Create(zipPath); err == nil {
		zw := zip.NewWriter(f)
		w, _ := zw.Create("readme.txt")
		_, _ = w.Write([]byte("hi"))
		_ = zw.Close()
		_ = f.Close()
	}
	zf, _ := os.Open(zipPath)
	if zf != nil {
		_, _ = store.Add("task", fmt.Sprint(task.ID), "bundle.zip", "archive", zf)
		_ = zf.Close()
	}

	svc := New(root, pg)
	res, err := svc.RunPrecheck(t.Context(), task.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.InferredCategory != "pwn" {
		t.Fatalf("expected inferred category pwn, got %q (tags=%v)", res.InferredCategory, res.Tags)
	}
	if len(res.Targets) < 2 {
		t.Fatalf("expected extracted targets (url + nc), got %v", res.Targets)
	}
	// Verify DB precheck_result and board_items L1-L3 fact created.
	raw, err := pg.TaskPrecheck(t.Context(), task.ID)
	if err != nil || len(raw) == 0 {
		t.Fatalf("TaskPrecheck empty: err=%v", err)
	}
	items, err := pg.ListBoardItems(t.Context(), task.ID, db.BoardKindFact)
	if err != nil || len(items) == 0 || items[0].Title != "Phase-0 Precheck 化验单" {
		t.Fatalf("expected precheck fact on board, got %+v err=%v", items, err)
	}
	// Cached call with force=false returns immediately without duplicating board item.
	res2, err := svc.RunPrecheck(t.Context(), task.ID, false)
	if err != nil || res2.InputHash != res.InputHash {
		t.Fatalf("expected cached precheck hit: res2=%+v err=%v", res2, err)
	}
	items2, _ := pg.ListBoardItems(t.Context(), task.ID, db.BoardKindFact)
	if len(items2) != len(items) {
		t.Fatalf("expected idempotent board precheck fact, got %d vs %d", len(items2), len(items))
	}
}

func TestVerifyCheckOracle(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("test database required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()

	task, err := pg.CreateTaskWithOptions("oracle-check", "find flag", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "pwn"})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)

	root := t.TempDir()
	svc := New(root, pg)
	svc.BindMount = true
	if err := svc.Sync(t.Context(), task.ID); err != nil {
		t.Fatal(err)
	}

	nextCode := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost && r.URL.Path == "/sessions" {
			var spec ctfrunner.SessionSpec
			_ = json.NewDecoder(r.Body).Decode(&spec)
			_ = json.NewEncoder(w).Encode(ctfrunner.Session{Spec: spec, ContainerID: "c-oracle", Name: "p3y-box-" + spec.Key(), InputsReady: true})
			return
		}
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/exec") {
			stdout := "LOCAL_OK"
			stderr := ""
			if nextCode != 0 {
				stdout = ""
				stderr = "AssertionError"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"exit_code":  nextCode,
				"stdout_b64": base64.StdEncoding.EncodeToString([]byte(stdout)),
				"stderr_b64": base64.StdEncoding.EncodeToString([]byte(stderr)),
			})
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	svc.Runner = &ctfrunner.Client{URL: srv.URL, Token: strings.Repeat("k", 24)}

	resPass, err := svc.VerifyCheck(context.Background(), task.ID, 1, "python3 /work/check.py", 30)
	if err != nil || !resPass.Passed || resPass.ExecutionID == "" {
		t.Fatalf("expected VerifyCheck pass, got %+v err=%v", resPass, err)
	}

	nextCode = 2
	resFail, err := svc.VerifyCheck(context.Background(), task.ID, 1, "python3 /work/check.py", 30)
	if err != nil || resFail.Passed || resFail.ExitCode != 2 {
		t.Fatalf("expected VerifyCheck fail with exit 2, got %+v err=%v", resFail, err)
	}
}

func TestRunPrecheckExtractsWebTextTagsAndBackfillsTips(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("test database required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()

	// Seed twice to verify idempotency and backfill of all 11 built-in cards.
	if err := pg.SeedDefaultTips(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := pg.SeedDefaultTips(t.Context()); err != nil {
		t.Fatal(err)
	}
	cards, err := pg.ListTips(t.Context(), "web", 50)
	if err != nil {
		t.Fatal(err)
	}
	foundNext := false
	for _, c := range cards {
		if strings.Contains(c.Title, "Next.js Middleware") {
			foundNext = true
			break
		}
	}
	if !foundNext {
		t.Fatalf("expected Next.js Middleware tip card to be backfilled, got %d web cards", len(cards))
	}

	task, err := pg.CreateTaskWithOptions("web-nextjs", "Target https://10.0.128.5:3000 Next.js app with middleware auth and SSRF endpoint", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "web"})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)

	svc := New(t.TempDir(), pg)
	res, err := svc.RunPrecheck(t.Context(), task.ID, true)
	if err != nil {
		t.Fatalf("RunPrecheck: %v", err)
	}
	tagMap := map[string]bool{}
	for _, tg := range res.Tags {
		tagMap[tg] = true
	}
	if !tagMap["nextjs"] || !tagMap["ssrf"] {
		t.Fatalf("expected text-extracted tags nextjs & ssrf on attachmentless Web task, got %v", res.Tags)
	}
	if len(res.MatchedTips) == 0 || !strings.Contains(res.MatchedTips[0].Title, "Next.js Middleware") {
		t.Fatalf("expected top matched tip card to be Next.js Middleware, got %+v", res.MatchedTips)
	}
}

func TestRunPrecheckZippedELFInfersPwnAndSharedScope(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("test database required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()

	task, err := pg.CreateTaskWithOptions(
		"Pwn | passbox",
		"提交 Rust 源码，服务端用 rustc 1.81.0（LLVM 18）编译并运行 smolstats pass；execve 被禁。靶场：47.112.26.126:36052",
		db.TaskCreateOptions{Mode: "ctf", ChallengeType: "auto"},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)

	root := t.TempDir()
	store := artifacts.Store{Root: root}
	zipPath := filepath.Join(t.TempDir(), "passbox.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, _ := zw.Create("chall/passrunner")
	_, _ = w.Write(buildMinimalELF64Header(62, 3))
	_ = zw.Close()
	_ = f.Close()

	zf, err := os.Open(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	defer zf.Close()
	if _, err := store.Add("task", fmt.Sprint(task.ID), "passbox.zip", "attachment", zf); err != nil {
		t.Fatal(err)
	}

	svc := New(root, pg)
	res, err := svc.RunPrecheck(t.Context(), task.ID, true)
	if err != nil {
		t.Fatalf("RunPrecheck: %v", err)
	}
	if res.InferredCategory != "pwn" {
		t.Fatalf("expected zipped ELF + target auto task to infer pwn, got %q (tags=%v)", res.InferredCategory, res.Tags)
	}
	sessionIntent, workDir, _, shared := svc.resolveScope(t.Context(), task.ID, 1737)
	if !shared || sessionIntent != 0 || !strings.HasSuffix(filepath.ToSlash(workDir), "/shared/ctf-work") {
		t.Fatalf("expected auto->pwn task to enable shared work dir, got shared=%v intent=%d workDir=%q", shared, sessionIntent, workDir)
	}
}
