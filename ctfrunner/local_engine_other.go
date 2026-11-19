//go:build !unix

package ctfrunner

import "os/exec"

func setProcessGroup(_ *exec.Cmd) {}

func killProcessGroup(_ int) {}
