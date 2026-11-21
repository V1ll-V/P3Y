package db

import (
	"regexp"
	"testing"
)

// 内置「删除类接口路径」规则匹配的是整个 tool_input JSON 串，因此用例直接以
// JSON 形态给出，与 Interceptor 实际拿到的 subject 一致。
func TestDeleteEndpointPathPattern(t *testing.T) {
	re := regexp.MustCompile(deleteEndpointPathPattern)

	hit := []string{
		`{"command":"curl -s 'http://t.com/api/user/delete?id=1'"}`,    // GET 打删除接口
		`{"command":"curl -X POST http://t.com/admin/delete -d id=1"}`, // POST 打删除接口
		`{"command":"curl 'http://t.com/api/deleteAll'"}`,
		`{"command":"curl 'http://t.com/api/delete_user?id=1'"}`,
		`{"command":"curl 'http://t.com/api/delete-user?id=1'"}`,
		`{"url":"http://t.com/api/remove?id=1"}`,
		`{"command":"curl http://t.com/files/unlink/3"}`,
		`{"command":"curl http://t.com/api/del?id=2"}`,
		`{"command":"curl -X POST http://t/v1/erase"}`,
		`{"command":"curl http://t/admin/destroyAll"}`, // v1 的路径规则不允许后缀，这里补上
	}
	for _, s := range hit {
		if !re.MatchString(s) {
			t.Errorf("应命中却放行: %s", s)
		}
	}

	// 动词后必须跟分隔符，避免 /delivery、/details 这类只读路径被误拦。
	miss := []string{
		`{"command":"curl 'http://t.com/api/delivery?id=1'"}`,
		`{"command":"curl 'http://t.com/order/details'"}`,
		`{"command":"curl 'http://t.com/api/delta/sync'"}`,
		`{"command":"curl 'http://t.com/user/delegate'"}`,
		`{"command":"curl 'http://delete.example.com/'"}`, // 删除动词出现在域名而非路径
		`{"command":"curl 'http://t.com/remote/status'"}`,
		`{"command":"nmap -p80 10.0.0.1"}`,
	}
	for _, s := range miss {
		if re.MatchString(s) {
			t.Errorf("误拦: %s", s)
		}
	}
}

func TestShutdownRebootAndDestructivePatterns(t *testing.T) {
	reShutdown := regexp.MustCompile(shutdownRebootPattern)
	reDestructive := regexp.MustCompile(destructiveShellPattern)
	for _, s := range []string{
		`{"command":"dd if=/dev/zero of=/dev/sda bs=1M"}`,
		`{"command":"rm -rf /"}`,
		`{"command":"rm -rf /*"}`,
	} {
		if !reDestructive.MatchString(s) {
			t.Errorf("destructiveShellPattern 应命中却放行: %s", s)
		}
	}
	for _, s := range []string{
		`{"command":"cd /work/k66 && dd if=bzImage bs=1 skip=16057 2>/dev/null | gzip -dc > out/vmlinux"}`,
		`{"command":"cd /tmp && rm -rf cpy315 && mkdir cpy315"}`,
	} {
		if reDestructive.MatchString(s) {
			t.Errorf("destructiveShellPattern 误拦: %s", s)
		}
	}

	hit := []string{
		`{"command":"shutdown -h now"}`,
		`{"command":"sudo shutdown now"}`,
		`{"command":"echo done && reboot"}`,
		`{"command":"echo done; /sbin/reboot -f"}`,
		`{"command":"echo done\npoweroff"}`,
		`{"command":"sudo halt"}`,
		`{"command":"/sbin/init 0"}`,
		`{"command":"init 6"}`,
	}
	for _, s := range hit {
		if !reShutdown.MatchString(s) {
			t.Errorf("shutdownRebootPattern 应命中却放行: %s", s)
		}
		if !reDestructive.MatchString(s) {
			t.Errorf("destructiveShellPattern 应命中却放行: %s", s)
		}
	}

	miss := []string{
		`{"command":"cat > /work/r12.py <<'PYEOF'\nimport socket\ns.shutdown(socket.SHUT_WR)\nPYEOF"}`,
		`{"command":"python3 -c 'import socket; s.shutdown(1)'"}`,
		`{"command":"python3 -c 'server.shutdown(); executor.shutdown(wait=False)'"}`,
		`{"command":"echo 'shutdown(fd, SHUT_WR)'"}`,
		`{"command":"grep -n shutdown /work/server.py"}`,
		`{"command":"python3 -c '\nhalt = True\nreboot = 0\n'"}`,
		`{"command":"curl http://10.0.0.1/status"}`,
	}
	for _, s := range miss {
		if reShutdown.MatchString(s) {
			t.Errorf("shutdownRebootPattern 误拦: %s", s)
		}
		if reDestructive.MatchString(s) {
			t.Errorf("destructiveShellPattern 误拦: %s", s)
		}
	}
}
