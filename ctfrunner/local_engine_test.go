package ctfrunner

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRewriteWorkPaths(t *testing.T) {
	const alias = "/tmp/p3y-w/abc123def456"
	cases := []struct {
		in   string
		want string
	}{
		{"ls -la /work", "ls -la " + alias},
		{"cat /work/.inputs/a1/original", "cat " + alias + "/.inputs/a1/original"},
		{`python3 "/work/solve.py" --work-dir=/work`, `python3 "` + alias + `/solve.py" --work-dir=` + alias},
		{"ls /workspace/foo /app/work/bar http://example.com/work/api", "ls /workspace/foo /app/work/bar http://example.com/work/api"},
	}
	for _, tc := range cases {
		if got := RewriteWorkPaths(tc.in, alias); got != tc.want {
			t.Fatalf("RewriteWorkPaths(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func makeTestInputsTar(t *testing.T, content string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: ".inputs/", Typeflag: tar.TypeDir, Mode: 0o555})
	_ = tw.WriteHeader(&tar.Header{Name: ".inputs/a1/", Typeflag: tar.TypeDir, Mode: 0o555})
	_ = tw.WriteHeader(&tar.Header{Name: ".inputs/a1/original", Typeflag: tar.TypeReg, Mode: 0o444, Size: int64(len(content))})
	_, _ = tw.Write([]byte(content))
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestLocalBackendExecIsolationSavepointAndTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("LocalBackend POSIX shell/symlink integration runs on Linux")
	}
	if _, err := exec.LookPath("/bin/bash"); err != nil {
		t.Skip("/bin/bash unavailable")
	}

	root := t.TempDir()
	shortWorkRoot, err := os.MkdirTemp("", "pw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(shortWorkRoot) })
	client, _ := NewLocalClient(shortWorkRoot, filepath.Join(root, "state"))
	ctx := context.Background()

	// Verify /health succeeds without Docker socket.
	h, err := client.Health(ctx)
	if err != nil || h["ok"] != true {
		t.Fatalf("Health failed: h=%+v err=%v", h, err)
	}

	hostWorkA := filepath.Join(root, "hostA")
	hostWorkB := filepath.Join(root, "hostB")
	specA := SessionSpec{TaskID: 101, IntentID: 1, InputHash: strings.Repeat("a", 64), HostWorkDir: hostWorkA}
	specB := SessionSpec{TaskID: 102, IntentID: 1, InputHash: strings.Repeat("b", 64), HostWorkDir: hostWorkB}

	if _, err := client.Prepare(ctx, specA); err != nil {
		t.Fatalf("Prepare A: %v", err)
	}
	if _, err := client.Prepare(ctx, specB); err != nil {
		t.Fatalf("Prepare B: %v", err)
	}
	if err := client.Upload(ctx, specA.Key(), true, bytes.NewReader(makeTestInputsTar(t, "INPUT_A"))); err != nil {
		t.Fatalf("Upload A: %v", err)
	}
	if err := client.Upload(ctx, specB.Key(), true, bytes.NewReader(makeTestInputsTar(t, "INPUT_B"))); err != nil {
		t.Fatalf("Upload B: %v", err)
	}

	// Concurrent tasks writing to /work/flag.txt must stay isolated and read their own .inputs.
	t.Setenv("OPENAI_API_KEY", "sk-secret-must-not-leak")
	t.Setenv("P3Y_PG_DSN", "postgres://secret-must-not-leak")
	resA, err := client.Execute(ctx, specA.Key(), `echo -n "FROM_A:" > /work/state.txt; cat /work/.inputs/a1/original >> /work/state.txt; cat /work/state.txt; echo "|KEY=${OPENAI_API_KEY:-}|DSN=${P3Y_PG_DSN:-}"`, 10)
	if err != nil || resA.ExitCode != 0 {
		t.Fatalf("Exec A failed: exit=%d err=%v stderr=%s", resA.ExitCode, err, resA.Stderr)
	}
	if !strings.Contains(string(resA.Stdout), "FROM_A:INPUT_A|KEY=|DSN=") {
		t.Fatalf("unexpected stdout A: %s", resA.Stdout)
	}

	resB, err := client.Execute(ctx, specB.Key(), `echo -n "FROM_B:" > /work/state.txt; cat /work/.inputs/a1/original >> /work/state.txt; cat /work/state.txt`, 10)
	if err != nil || resB.ExitCode != 0 {
		t.Fatalf("Exec B failed: exit=%d err=%v stderr=%s", resB.ExitCode, err, resB.Stderr)
	}
	if strings.TrimSpace(string(resB.Stdout)) != "FROM_B:INPUT_B" {
		t.Fatalf("unexpected stdout B: %s", resB.Stdout)
	}
	// Verify A's file was untouched by B.
	rawA, err := os.ReadFile(filepath.Join(hostWorkA, "state.txt"))
	if err != nil || string(rawA) != "FROM_A:INPUT_A" {
		t.Fatalf("hostWorkA polluted or missing: %q err=%v", rawA, err)
	}

	// Verify Savepoint + Rewind restores clean state.
	sp, err := client.CreateSavepoint(ctx, specA.Key(), "sp-clean")
	if err != nil || sp.ID != "sp-clean" {
		t.Fatalf("CreateSavepoint: sp=%+v err=%v", sp, err)
	}
	if _, err := client.Execute(ctx, specA.Key(), `echo "CORRUPTED" > /work/state.txt`, 10); err != nil {
		t.Fatalf("corrupt file: %v", err)
	}
	rw, err := client.Rewind(ctx, specA.Key(), "sp-clean")
	if err != nil || !rw.Rewound {
		t.Fatalf("Rewind: rw=%+v err=%v", rw, err)
	}
	rawA2, err := os.ReadFile(filepath.Join(hostWorkA, "state.txt"))
	if err != nil || string(rawA2) != "FROM_A:INPUT_A" {
		t.Fatalf("expected state.txt restored after Rewind, got %q err=%v", rawA2, err)
	}

	// Verify timeout terminates command cleanly with code 124.
	toRes, err := client.Execute(ctx, specA.Key(), `sleep 10`, 1)
	if err != nil || toRes.ExitCode != 124 {
		t.Fatalf("expected timeout exit 124, got exit=%d err=%v", toRes.ExitCode, err)
	}

	// Verify interactive PTY and background jobs when python3 exists.
	if _, pyErr := exec.LookPath("/usr/bin/python3"); pyErr == nil {
		job, jerr := client.StartJob(ctx, specA.Key(), "echo bg_done", "job1", "exec-1")
		if jerr != nil || job.ID != "job1" {
			t.Fatalf("StartJob: job=%+v err=%v", job, jerr)
		}
		_ = client.StopJob(ctx, specA.Key(), "job1")

		ptyInfo, perr := client.StartInteractive(ctx, specA.Key(), "/bin/cat", "pty1", "exec-2")
		if perr != nil || ptyInfo.ID != "pty1" {
			t.Fatalf("StartInteractive: info=%+v err=%v", ptyInfo, perr)
		}
		if _, werr := client.WriteInteractive(ctx, specA.Key(), "pty1", "hello_pty", "utf-8", true); werr != nil {
			t.Fatalf("WriteInteractive: %v", werr)
		}
		rr, rerr := client.ReadInteractive(ctx, specA.Key(), "pty1", 0, 1000)
		if rerr != nil || !strings.Contains(rr.Output, "hello_pty") {
			t.Fatalf("ReadInteractive: rr=%+v err=%v", rr, rerr)
		}
		_ = client.CloseInteractive(ctx, specA.Key(), "pty1")
	}

	// Verify Download archive works from LocalBackend.
	dl, derr := client.Download(ctx, specA.Key())
	if derr != nil {
		t.Fatalf("Download: %v", derr)
	}
	_ = dl.Close()

	if err := client.Delete(ctx, specA.Key()); err != nil {
		t.Fatalf("Delete session A: %v", err)
	}
	if err := client.Delete(ctx, specB.Key()); err != nil {
		t.Fatalf("Delete session B: %v", err)
	}
}
