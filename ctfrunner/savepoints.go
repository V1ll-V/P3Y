package ctfrunner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var savepointIDPattern = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)

type savepointRequest struct {
	ID string `json:"id"`
}

func (s *Server) createSavepoint(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("id")
	var req savepointRequest
	if r.Body != nil {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil && !strings.Contains(err.Error(), "EOF") {
			fail(w, errors.New("invalid savepoint request"))
			return
		}
	}
	id := strings.TrimSpace(req.ID)
	if id == "" {
		id = "sp-" + strconv.FormatInt(time.Now().UTC().UnixNano(), 10)
	}
	if !savepointIDPattern.MatchString(id) {
		fail(w, errors.New("invalid savepoint id"))
		return
	}

	unlock := s.lock(key)
	defer unlock()
	v, err := s.load(key)
	if err != nil {
		fail(w, err)
		return
	}

	snapDir := "/work/.snapshots/" + id
	tmpDir := snapDir + ".tmp"
	// Copy all user files/dirs/dotfiles from /work via hardlinks on the same filesystem,
	// excluding read-only inputs and internal caches/metadata directories.
	script := fmt.Sprintf(`set -e
mkdir -p /work/.snapshots
rm -rf %s
mkdir -p %s
find /work -mindepth 1 -maxdepth 1 ! -name '.inputs' ! -name '.snapshots' ! -name '.ghidra' ! -name '.cache' ! -name '.jobs' ! -name '.interactive' -exec cp -al -- {} %s/ \;
rm -rf %s
mv %s %s`,
		shQuote(tmpDir), shQuote(tmpDir), shQuote(tmpDir), shQuote(snapDir), shQuote(tmpDir), shQuote(snapDir),
	)

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	res, err := s.Engine.Exec(ctx, v.ContainerID, script)
	if err != nil {
		fail(w, err)
		return
	}
	if res.ExitCode != 0 {
		msg := strings.TrimSpace(string(res.Stderr))
		if msg == "" {
			msg = fmt.Sprintf("savepoint command exited with code %d", res.ExitCode)
		}
		fail(w, errors.New(msg))
		return
	}
	_ = s.save(v)
	reply(w, 200, SavepointResult{ID: id, Path: snapDir})
}

func (s *Server) rewindSavepoint(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("id")
	var req savepointRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		fail(w, errors.New("invalid rewind request"))
		return
	}
	id := strings.TrimSpace(req.ID)
	if !savepointIDPattern.MatchString(id) {
		fail(w, errors.New("invalid savepoint id"))
		return
	}

	unlock := s.lock(key)
	defer unlock()
	v, err := s.load(key)
	if err != nil {
		fail(w, err)
		return
	}

	snapDir := "/work/.snapshots/" + id
	// Verify snapshot exists, terminate stray background solver/script processes holding
	// files under /work (without touching PID 1 sleep or this shell), clear /work user
	// files, and restore the hardlink snapshot back into /work.
	script := fmt.Sprintf(`set -e
test -d %s || { echo "savepoint not found" >&2; exit 44; }
for c in /proc/[0-9]*/cmdline; do
  pid=${c#/proc/}
  pid=${pid%%/cmdline}
  [ "$pid" = "1" ] || [ "$pid" = "$$" ] || [ "$pid" = "$PPID" ] && continue
  cmd=$(tr '\0' ' ' < "$c" 2>/dev/null || true)
  case "$cmd" in
    *"/work/"*) kill -TERM "$pid" 2>/dev/null || true ;;
  esac
done
find /work -mindepth 1 -maxdepth 1 ! -name '.inputs' ! -name '.snapshots' ! -name '.ghidra' ! -name '.cache' ! -name '.jobs' ! -name '.interactive' -exec rm -rf -- {} +
find %s -mindepth 1 -maxdepth 1 -exec cp -al -- {} /work/ \;`,
		shQuote(snapDir), shQuote(snapDir),
	)

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	res, err := s.Engine.Exec(ctx, v.ContainerID, script)
	if err != nil {
		fail(w, err)
		return
	}
	if res.ExitCode == 44 {
		reply(w, 404, map[string]string{"error": "savepoint not found"})
		return
	}
	if res.ExitCode != 0 {
		msg := strings.TrimSpace(string(res.Stderr))
		if msg == "" {
			msg = fmt.Sprintf("rewind command exited with code %d", res.ExitCode)
		}
		fail(w, errors.New(msg))
		return
	}
	_ = s.save(v)
	reply(w, 200, RewindResult{ID: id, Rewound: true})
}

func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
