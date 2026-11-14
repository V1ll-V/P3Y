package ctf

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"p3y/artifacts"
	"p3y/ctfrunner"
)

func (s *Service) sessionSpec(ctx context.Context, task, sessionIntent int64, m artifacts.Manifest, localWork string) (ctfrunner.SessionSpec, error) {
	spec := ctfrunner.SessionSpec{TaskID: task, IntentID: sessionIntent, InputHash: Hash(m)}
	if s.bindMountEnabled() && localWork != "" {
		spec.HostWorkDir = s.hostBindPath(localWork)
	}
	if env := s.containerProxyEnv(); len(env) > 0 {
		spec.Env = env
	}
	if s.DB == nil {
		return spec, nil
	}
	_, vpnHash, _, err := s.DB.TaskCTFVPN(ctx, task)
	if err != nil {
		return spec, fmt.Errorf("读取 CTF VPN 状态失败：%w", err)
	}
	spec.VPNHash = strings.TrimSpace(vpnHash)
	return spec, nil
}

func (s *Service) containerProxyEnv() map[string]string {
	if s == nil {
		return nil
	}
	if rawURL := strings.TrimSpace(os.Getenv("P3Y_BOX_PROXY_URL")); rawURL != "" {
		return buildContainerProxyEnv(rawURL)
	}
	addr := strings.TrimSpace(s.ProxyAddr)
	if addr == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err == nil {
		if host == "" || host == "127.0.0.1" || host == "localhost" || host == "0.0.0.0" || host == "::1" || host == "::" {
			proxyHost := strings.TrimSpace(os.Getenv("P3Y_BOX_PROXY_HOST"))
			if proxyHost == "" {
				// Docker containers cannot reach app loopback via 127.0.0.1 directly; use
				// host.docker.internal unless overridden for Linux/Compose setups.
				proxyHost = "host.docker.internal"
			}
			addr = net.JoinHostPort(proxyHost, port)
		}
	}
	return buildContainerProxyEnv("http://" + addr)
}

func buildContainerProxyEnv(proxyURL string) map[string]string {
	return map[string]string{
		"HTTP_PROXY":  proxyURL,
		"HTTPS_PROXY": proxyURL,
		"http_proxy":  proxyURL,
		"https_proxy": proxyURL,
		"NO_PROXY":    "127.0.0.1,localhost,.internal",
		"no_proxy":    "127.0.0.1,localhost,.internal",
	}
}

// CleanupTask removes all managed runner containers, VPN sidecars, and volumes for task.
func (s *Service) CleanupTask(ctx context.Context, task int64) error {
	if s == nil || s.Runner == nil || !s.Runner.Configured() || task <= 0 {
		return nil
	}
	return s.Runner.DeleteTaskResources(ctx, task)
}
