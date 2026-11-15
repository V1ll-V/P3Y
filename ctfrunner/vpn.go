package ctfrunner

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const (
	// MaxVPNConfigBytes caps uploaded VPN config size at 128 KiB.
	MaxVPNConfigBytes = 128 * 1024
	defaultVPNMTU     = 0

	VPNKindWireGuard = "wireguard"
	VPNKindOpenVPN   = "openvpn"
)

// VPNProfile represents a strictly validated, sanitized WireGuard or OpenVPN client config
// with shell-executing hooks stripped/rejected.
type VPNProfile struct {
	Kind                string   `json:"kind"`
	Proto               string   `json:"proto,omitempty"`
	RawSanitized        string   `json:"-"`
	RunnerConfig        string   `json:"-"`
	Hash                string   `json:"hash"`
	Address             string   `json:"address,omitempty"`
	Addresses           []string `json:"addresses,omitempty"`
	DNS                 []string `json:"dns,omitempty"`
	MTU                 int      `json:"mtu,omitempty"`
	Endpoint            string   `json:"endpoint,omitempty"`
	AllowedIPs          []string `json:"allowed_ips,omitempty"`
	PersistentKeepalive int      `json:"persistent_keepalive,omitempty"`
	PeerCount           int      `json:"peer_count"`
}

// VPNSummary is the non-secret public view of a task's VPN config.
type VPNSummary struct {
	Enabled             bool       `json:"enabled"`
	Kind                string     `json:"kind,omitempty"`
	Proto               string     `json:"proto,omitempty"`
	Filename            string     `json:"filename,omitempty"`
	Hash                string     `json:"hash,omitempty"`
	Address             string     `json:"address,omitempty"`
	DNS                 []string   `json:"dns,omitempty"`
	MTU                 int        `json:"mtu,omitempty"`
	Endpoint            string     `json:"endpoint,omitempty"`
	AllowedIPs          []string   `json:"allowed_ips,omitempty"`
	PersistentKeepalive int        `json:"persistent_keepalive,omitempty"`
	PeerCount           int        `json:"peer_count,omitempty"`
	Sidecar             *VPNStatus `json:"sidecar,omitempty"`
}

// VPNStatus describes the live state of a task's VPN sidecar container.
type VPNStatus struct {
	TaskID       int64  `json:"task_id"`
	Kind         string `json:"kind,omitempty"`
	Active       bool   `json:"active"`
	Running      bool   `json:"running"`
	Hash         string `json:"hash,omitempty"`
	ContainerID  string `json:"container_id,omitempty"`
	Container    string `json:"container,omitempty"`
	Network      string `json:"network,omitempty"`
	Interface    string `json:"interface,omitempty"`
	TunnelIP     string `json:"tunnel_ip,omitempty"`
	Endpoint     string `json:"endpoint,omitempty"`
	HandshakeAt  string `json:"handshake_at,omitempty"`
	HandshakeAge int64  `json:"handshake_age_sec,omitempty"`
	RxBytes      int64  `json:"rx_bytes,omitempty"`
	TxBytes      int64  `json:"tx_bytes,omitempty"`
	DNS          string `json:"dns,omitempty"`
	Error        string `json:"error,omitempty"`
}

type wgPeer struct {
	PublicKey           string
	PresharedKey        string
	Endpoint            string
	AllowedIPs          []string
	PersistentKeepalive int
}

// ParseWireGuardConfig strictly parses and validates a WireGuard INI config.
// Only standard client directives are permitted; shell-executing hooks such as
// PreUp/PostUp/PreDown/PostDown/SaveConfig/Table are explicitly rejected.
func ParseWireGuardConfig(raw string) (VPNProfile, error) {
	if len(raw) == 0 || strings.TrimSpace(raw) == "" {
		return VPNProfile{}, errors.New("WireGuard 配置内容为空")
	}
	if len(raw) > MaxVPNConfigBytes {
		return VPNProfile{}, fmt.Errorf("WireGuard 配置过大（上限 %d KiB）", MaxVPNConfigBytes/1024)
	}
	if strings.ContainsRune(raw, '\x00') {
		return VPNProfile{}, errors.New("WireGuard 配置包含非法空字节")
	}

	var (
		inInterface  bool
		seenIfc      bool
		currentPeer  *wgPeer
		peers        []*wgPeer
		privKey      string
		addresses    []string
		dnsServers   []string
		mtu          int
		seenIfcKeys  = map[string]bool{}
		seenPeerKeys map[string]bool
	)

	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	for lineNo, line := range lines {
		for _, r := range line {
			if r < 0x20 && r != '\t' {
				return VPNProfile{}, fmt.Errorf("第 %d 行包含非法控制字符", lineNo+1)
			}
		}
		if idx := strings.IndexAny(line, "#;"); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			sec := strings.TrimSpace(line[1 : len(line)-1])
			switch {
			case strings.EqualFold(sec, "Interface"):
				if seenIfc {
					return VPNProfile{}, errors.New("WireGuard 配置包含重复的 [Interface] 段")
				}
				seenIfc = true
				inInterface = true
				currentPeer = nil
			case strings.EqualFold(sec, "Peer"):
				inInterface = false
				currentPeer = &wgPeer{}
				peers = append(peers, currentPeer)
				seenPeerKeys = map[string]bool{}
			default:
				return VPNProfile{}, fmt.Errorf("第 %d 行包含不支持的配置段 [%s]", lineNo+1, sec)
			}
			continue
		}
		if !seenIfc && currentPeer == nil {
			return VPNProfile{}, fmt.Errorf("第 %d 行缺少所属配置段（[Interface] 或 [Peer]）", lineNo+1)
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			return VPNProfile{}, fmt.Errorf("第 %d 行格式错误，应为 key = value", lineNo+1)
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		if val == "" {
			return VPNProfile{}, fmt.Errorf("第 %d 行字段 %q 值为空", lineNo+1, key)
		}

		lowerKey := strings.ToLower(key)
		if inInterface {
			switch lowerKey {
			case "privatekey":
				if seenIfcKeys["privatekey"] {
					return VPNProfile{}, fmt.Errorf("第 %d 行重复设置 PrivateKey", lineNo+1)
				}
				if err := validateWGKey(val); err != nil {
					return VPNProfile{}, fmt.Errorf("第 %d 行 PrivateKey 无效：%w", lineNo+1, err)
				}
				privKey = val
				seenIfcKeys["privatekey"] = true
			case "address":
				items, err := parseCIDRList(val)
				if err != nil {
					return VPNProfile{}, fmt.Errorf("第 %d 行 Address 无效：%w", lineNo+1, err)
				}
				addresses = append(addresses, items...)
				seenIfcKeys["address"] = true
			case "dns":
				items, err := parseIPList(val)
				if err != nil {
					return VPNProfile{}, fmt.Errorf("第 %d 行 DNS 无效：%w", lineNo+1, err)
				}
				dnsServers = append(dnsServers, items...)
				seenIfcKeys["dns"] = true
			case "mtu":
				if seenIfcKeys["mtu"] {
					return VPNProfile{}, fmt.Errorf("第 %d 行重复设置 MTU", lineNo+1)
				}
				n, err := strconv.Atoi(val)
				if err != nil || n < 576 || n > 9000 {
					return VPNProfile{}, fmt.Errorf("第 %d 行 MTU 无效（须在 576~9000 之间）", lineNo+1)
				}
				mtu = n
				seenIfcKeys["mtu"] = true
			default:
				return VPNProfile{}, fmt.Errorf("第 %d 行包含不支持或存在安全风险的字段 %q", lineNo+1, key)
			}
			continue
		}

		if currentPeer == nil {
			return VPNProfile{}, fmt.Errorf("第 %d 行必须位于 [Interface] 或 [Peer] 段内", lineNo+1)
		}
		switch lowerKey {
		case "publickey":
			if seenPeerKeys["publickey"] {
				return VPNProfile{}, fmt.Errorf("第 %d 行重复设置 Peer.PublicKey", lineNo+1)
			}
			if err := validateWGKey(val); err != nil {
				return VPNProfile{}, fmt.Errorf("第 %d 行 PublicKey 无效：%w", lineNo+1, err)
			}
			currentPeer.PublicKey = val
			seenPeerKeys["publickey"] = true
		case "presharedkey":
			if seenPeerKeys["presharedkey"] {
				return VPNProfile{}, fmt.Errorf("第 %d 行重复设置 Peer.PresharedKey", lineNo+1)
			}
			if err := validateWGKey(val); err != nil {
				return VPNProfile{}, fmt.Errorf("第 %d 行 PresharedKey 无效：%w", lineNo+1, err)
			}
			currentPeer.PresharedKey = val
			seenPeerKeys["presharedkey"] = true
		case "endpoint":
			if seenPeerKeys["endpoint"] {
				return VPNProfile{}, fmt.Errorf("第 %d 行重复设置 Peer.Endpoint", lineNo+1)
			}
			ep, err := validateEndpoint(val)
			if err != nil {
				return VPNProfile{}, fmt.Errorf("第 %d 行 Endpoint 无效：%w", lineNo+1, err)
			}
			currentPeer.Endpoint = ep
			seenPeerKeys["endpoint"] = true
		case "allowedips":
			items, err := parseCIDRList(val)
			if err != nil {
				return VPNProfile{}, fmt.Errorf("第 %d 行 AllowedIPs 无效：%w", lineNo+1, err)
			}
			currentPeer.AllowedIPs = append(currentPeer.AllowedIPs, items...)
			seenPeerKeys["allowedips"] = true
		case "persistentkeepalive":
			if seenPeerKeys["persistentkeepalive"] {
				return VPNProfile{}, fmt.Errorf("第 %d 行重复设置 PersistentKeepalive", lineNo+1)
			}
			n, err := strconv.Atoi(val)
			if err != nil || n < 0 || n > 65535 {
				return VPNProfile{}, fmt.Errorf("第 %d 行 PersistentKeepalive 无效（0~65535）", lineNo+1)
			}
			currentPeer.PersistentKeepalive = n
			seenPeerKeys["persistentkeepalive"] = true
		default:
			return VPNProfile{}, fmt.Errorf("第 %d 行包含不支持或存在安全风险的字段 %q", lineNo+1, key)
		}
	}

	if !seenIfc || privKey == "" || len(addresses) == 0 {
		return VPNProfile{}, errors.New("WireGuard [Interface] 必须包含 PrivateKey 与 Address")
	}
	if len(peers) == 0 {
		return VPNProfile{}, errors.New("WireGuard 配置至少需要一个 [Peer] 段")
	}
	var allAllowed []string
	for i, peer := range peers {
		if peer.PublicKey == "" || peer.Endpoint == "" || len(peer.AllowedIPs) == 0 {
			return VPNProfile{}, fmt.Errorf("第 %d 个 [Peer] 必须包含 PublicKey、Endpoint 与 AllowedIPs", i+1)
		}
		allAllowed = append(allAllowed, peer.AllowedIPs...)
	}

	sanitized := renderWGConfig(privKey, addresses, dnsServers, mtu, peers, true)
	runnerConf := renderWGConfig(privKey, addresses, nil, mtu, peers, false)
	sum := sha256.Sum256([]byte(sanitized))
	keepalive := peers[0].PersistentKeepalive
	return VPNProfile{
		Kind:                VPNKindWireGuard,
		RawSanitized:        sanitized,
		RunnerConfig:        runnerConf,
		Hash:                hex.EncodeToString(sum[:]),
		Address:             strings.Join(addresses, ", "),
		Addresses:           addresses,
		DNS:                 dnsServers,
		MTU:                 mtu,
		Endpoint:            peers[0].Endpoint,
		AllowedIPs:          allAllowed,
		PersistentKeepalive: keepalive,
		PeerCount:           len(peers),
	}, nil
}

// DetectVPNKind inspects configuration content and returns "wireguard", "openvpn", or "".
func DetectVPNKind(raw string) string {
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	hasWGSection := false
	ovpnSignals := 0
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
			continue
		}
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			sec := strings.ToLower(strings.TrimSpace(t[1 : len(t)-1]))
			if sec == "interface" || sec == "peer" {
				hasWGSection = true
			}
		}
		lower := strings.ToLower(t)
		switch {
		case lower == "client" || lower == "tls-client" ||
			strings.HasPrefix(lower, "remote ") ||
			strings.HasPrefix(lower, "proto ") ||
			strings.HasPrefix(lower, "dev ") ||
			lower == "<ca>" || lower == "<cert>" || lower == "<key>" ||
			lower == "<tls-auth>" || lower == "<tls-crypt>" || lower == "<tls-crypt-v2>":
			ovpnSignals++
		}
	}
	if hasWGSection {
		return VPNKindWireGuard
	}
	if ovpnSignals > 0 {
		return VPNKindOpenVPN
	}
	return ""
}

// ParseVPNConfig auto-detects and strictly validates either WireGuard (.conf) or OpenVPN (.ovpn) client configs.
func ParseVPNConfig(raw string) (VPNProfile, error) {
	if strings.TrimSpace(raw) == "" {
		return VPNProfile{}, errors.New("VPN 配置内容为空")
	}
	if len(raw) > MaxVPNConfigBytes {
		return VPNProfile{}, fmt.Errorf("VPN 配置文件过大（上限 %d KiB）", MaxVPNConfigBytes/1024)
	}
	if strings.ContainsRune(raw, '\x00') {
		return VPNProfile{}, errors.New("VPN 配置包含非法空字节")
	}
	switch DetectVPNKind(raw) {
	case VPNKindWireGuard:
		return ParseWireGuardConfig(raw)
	case VPNKindOpenVPN:
		return ParseOpenVPNConfig(raw)
	default:
		return VPNProfile{}, errors.New("无法识别的 VPN 配置格式，请提供有效的 WireGuard (.conf) 或 OpenVPN (.ovpn) 配置")
	}
}

var allowedOVPNInlineTags = map[string]bool{
	"ca":             true,
	"cert":           true,
	"key":            true,
	"tls-auth":       true,
	"tls-crypt":      true,
	"tls-crypt-v2":   true,
	"extra-certs":    true,
	"crl-verify":     true,
	"secret":         true,
	"auth-user-pass": true,
}

var blockedOVPNDirectives = map[string]bool{
	"plugin":                true,
	"chroot":                true,
	"management":            true,
	"askpass":               true,
	"pkcs12":                true,
	"ipchange":              true,
	"route-up":              true,
	"route-pre-down":        true,
	"client-connect":        true,
	"client-disconnect":     true,
	"learn-address":         true,
	"auth-user-pass-verify": true,
	"tls-verify":            true,
	"tls-crypt-v2-verify":   true,
	"tmp-dir":               true,
	"log":                   true,
	"log-append":            true,
	"writepid":              true,
	"status":                true,
	"daemon":                true,
}

var fileRefOVPNDirectives = map[string]bool{
	"ca":             true,
	"cert":           true,
	"key":            true,
	"tls-auth":       true,
	"tls-crypt":      true,
	"tls-crypt-v2":   true,
	"extra-certs":    true,
	"crl-verify":     true,
	"secret":         true,
	"auth-user-pass": true,
}

func isBenignOVPNResolvHook(fields []string) bool {
	if len(fields) < 2 {
		return false
	}
	script := strings.TrimSpace(fields[1])
	return script == "/etc/openvpn/update-resolv-conf" || script == "/etc/openvpn/update-systemd-resolved"
}

// ParseOpenVPNConfig validates an inline-cert OpenVPN client (.ovpn) config,
// stripping benign desktop resolv hooks while blocking arbitrary script/file-access directives.
func ParseOpenVPNConfig(raw string) (VPNProfile, error) {
	if strings.TrimSpace(raw) == "" {
		return VPNProfile{}, errors.New("OpenVPN 配置内容为空")
	}
	if len(raw) > MaxVPNConfigBytes {
		return VPNProfile{}, fmt.Errorf("OpenVPN 配置过大（上限 %d KiB）", MaxVPNConfigBytes/1024)
	}
	if strings.ContainsRune(raw, '\x00') {
		return VPNProfile{}, errors.New("OpenVPN 配置包含非法空字节")
	}

	var (
		sanitizedLines []string
		inBlockTag     string
		hasClient      bool
		remotes        []string
		proto          string
		addresses      []string
		dnsServers     []string
		routes         []string
		mtu            int
	)

	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	for lineNo, rawLine := range lines {
		for _, r := range rawLine {
			if r < 0x20 && r != '\t' {
				return VPNProfile{}, fmt.Errorf("第 %d 行包含非法控制字符", lineNo+1)
			}
		}
		trimmed := strings.TrimSpace(rawLine)
		if inBlockTag != "" {
			closeTag := "</" + inBlockTag + ">"
			if strings.EqualFold(trimmed, closeTag) {
				sanitizedLines = append(sanitizedLines, closeTag)
				inBlockTag = ""
			} else {
				sanitizedLines = append(sanitizedLines, strings.TrimRight(rawLine, " \t\r"))
			}
			continue
		}
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, "<") && strings.HasSuffix(trimmed, ">") && !strings.HasPrefix(trimmed, "</") {
			tag := strings.ToLower(strings.TrimSpace(trimmed[1 : len(trimmed)-1]))
			if !allowedOVPNInlineTags[tag] {
				return VPNProfile{}, fmt.Errorf("第 %d 行包含不支持的内联块 <%s>", lineNo+1, tag)
			}
			inBlockTag = tag
			sanitizedLines = append(sanitizedLines, "<"+tag+">")
			continue
		}
		if strings.HasPrefix(trimmed, "</") {
			return VPNProfile{}, fmt.Errorf("第 %d 行存在未匹配的结束标签 %s", lineNo+1, trimmed)
		}

		// Strip inline comments only outside quoted/PEM sections.
		line := trimmed
		if idx := strings.IndexAny(line, "#;"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		dir := strings.ToLower(fields[0])

		switch dir {
		case "user", "group":
			// Drop privilege-downgrade directives because the sidecar container runs isolated with minimal caps (without CAP_SETUID/CAP_SETGID).
			continue
		case "script-security":
			// Allow benign desktop boilerplate `script-security 0|1|2`, strip from runner config (container runs --script-security 0).
			if len(fields) >= 2 && (fields[1] == "0" || fields[1] == "1" || fields[1] == "2") {
				continue
			}
			return VPNProfile{}, fmt.Errorf("第 %d 行禁止设置危险的 script-security 级别", lineNo+1)
		case "up", "down":
			if isBenignOVPNResolvHook(fields) {
				continue
			}
			return VPNProfile{}, fmt.Errorf("第 %d 行出于安全策略禁止自定义 %s 脚本指令", lineNo+1, dir)
		}
		if blockedOVPNDirectives[dir] {
			return VPNProfile{}, fmt.Errorf("第 %d 行出于安全策略禁止指令 %q", lineNo+1, fields[0])
		}
		if fileRefOVPNDirectives[dir] && len(fields) >= 2 {
			return VPNProfile{}, fmt.Errorf("第 %d 行 %s 不允许引用外部本地文件路径，请使用内联 <%s>...</%s> 块", lineNo+1, fields[0], dir, dir)
		}

		switch dir {
		case "client", "tls-client":
			hasClient = true
		case "dev":
			if len(fields) < 2 {
				return VPNProfile{}, fmt.Errorf("第 %d 行 dev 缺少设备类型", lineNo+1)
			}
			devName := strings.ToLower(fields[1])
			if !strings.HasPrefix(devName, "tun") && !strings.HasPrefix(devName, "tap") {
				return VPNProfile{}, fmt.Errorf("第 %d 行 dev 设备类型 %q 不受支持（仅支持 tun/tap）", lineNo+1, fields[1])
			}
		case "proto":
			if len(fields) < 2 {
				return VPNProfile{}, fmt.Errorf("第 %d 行 proto 缺少协议值", lineNo+1)
			}
			p := strings.ToLower(fields[1])
			switch p {
			case "udp", "udp4", "udp6", "tcp", "tcp4", "tcp6", "tcp-client":
				proto = p
			default:
				return VPNProfile{}, fmt.Errorf("第 %d 行不支持的协议 %q", lineNo+1, fields[1])
			}
		case "remote":
			if len(fields) < 2 {
				return VPNProfile{}, fmt.Errorf("第 %d 行 remote 缺少服务器地址", lineNo+1)
			}
			host := fields[1]
			if _, err := netip.ParseAddr(host); err != nil && !isSafeHostname(host) {
				return VPNProfile{}, fmt.Errorf("第 %d 行 remote 主机名 %q 包含非法字符", lineNo+1, host)
			}
			port := "1194"
			if len(fields) >= 3 {
				pNum, err := strconv.Atoi(fields[2])
				if err != nil || pNum < 1 || pNum > 65535 {
					return VPNProfile{}, fmt.Errorf("第 %d 行 remote 端口 %q 无效（1~65535）", lineNo+1, fields[2])
				}
				port = fields[2]
			}
			if len(fields) >= 4 && proto == "" {
				proto = strings.ToLower(fields[3])
			}
			remotes = append(remotes, net.JoinHostPort(host, port))
		case "dhcp-option":
			if len(fields) >= 3 && strings.EqualFold(fields[1], "DNS") {
				if addr, err := netip.ParseAddr(fields[2]); err == nil {
					dnsServers = append(dnsServers, addr.String())
				} else {
					return VPNProfile{}, fmt.Errorf("第 %d 行 dhcp-option DNS %q 无效", lineNo+1, fields[2])
				}
			}
		case "ifconfig":
			hasClient = true
			if len(fields) >= 2 {
				if addr, err := netip.ParseAddr(fields[1]); err == nil {
					addresses = append(addresses, addr.String())
				}
			}
		case "route":
			if len(fields) >= 2 {
				if len(fields) >= 3 && strings.Contains(fields[2], ".") {
					routes = append(routes, fields[1]+"/"+fields[2])
				} else {
					routes = append(routes, fields[1])
				}
			}
		case "tun-mtu":
			if len(fields) >= 2 {
				if n, err := strconv.Atoi(fields[1]); err == nil && n >= 576 && n <= 9000 {
					mtu = n
				}
			}
		}

		sanitizedLines = append(sanitizedLines, line)
	}

	if inBlockTag != "" {
		return VPNProfile{}, fmt.Errorf("OpenVPN 配置内联块 <%s> 未正常闭合", inBlockTag)
	}
	if len(remotes) == 0 {
		return VPNProfile{}, errors.New("OpenVPN 配置缺少有效的 remote 服务器地址")
	}
	if !hasClient {
		return VPNProfile{}, errors.New("OpenVPN 配置缺少 client / tls-client 客户端声明")
	}

	sanitized := strings.Join(sanitizedLines, "\n") + "\n"
	sum := sha256.Sum256([]byte(sanitized))
	addrStr := strings.Join(addresses, ", ")
	if addrStr == "" {
		addrStr = "由服务端动态下发"
	}
	if len(routes) == 0 {
		routes = []string{"由服务端下发路由"}
	}
	return VPNProfile{
		Kind:         VPNKindOpenVPN,
		Proto:        proto,
		RawSanitized: sanitized,
		RunnerConfig: sanitized,
		Hash:         hex.EncodeToString(sum[:]),
		Address:      addrStr,
		Addresses:    addresses,
		DNS:          dnsServers,
		MTU:          mtu,
		Endpoint:     remotes[0],
		AllowedIPs:   routes,
		PeerCount:    len(remotes),
	}, nil
}

// Summary converts a parsed VPNProfile into its safe, secret-free UI DTO.
func (p VPNProfile) Summary(filename string) VPNSummary {
	if p.Hash == "" {
		return VPNSummary{Enabled: false}
	}
	kind := p.Kind
	if kind == "" {
		kind = VPNKindWireGuard
	}
	return VPNSummary{
		Enabled:             true,
		Kind:                kind,
		Proto:               p.Proto,
		Filename:            filename,
		Hash:                p.Hash,
		Address:             p.Address,
		DNS:                 append([]string(nil), p.DNS...),
		MTU:                 p.MTU,
		Endpoint:            p.Endpoint,
		AllowedIPs:          append([]string(nil), p.AllowedIPs...),
		PersistentKeepalive: p.PersistentKeepalive,
		PeerCount:           p.PeerCount,
	}
}

func renderWGConfig(privKey string, addresses, dns []string, mtu int, peers []*wgPeer, includeDNS bool) string {
	var b bytes.Buffer
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", privKey)
	fmt.Fprintf(&b, "Address = %s\n", strings.Join(addresses, ", "))
	if includeDNS && len(dns) > 0 {
		fmt.Fprintf(&b, "DNS = %s\n", strings.Join(dns, ", "))
	}
	if mtu > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", mtu)
	}
	for _, p := range peers {
		b.WriteString("\n[Peer]\n")
		fmt.Fprintf(&b, "PublicKey = %s\n", p.PublicKey)
		if p.PresharedKey != "" {
			fmt.Fprintf(&b, "PresharedKey = %s\n", p.PresharedKey)
		}
		fmt.Fprintf(&b, "Endpoint = %s\n", p.Endpoint)
		fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(p.AllowedIPs, ", "))
		if p.PersistentKeepalive > 0 {
			fmt.Fprintf(&b, "PersistentKeepalive = %d\n", p.PersistentKeepalive)
		}
	}
	return b.String()
}

func validateWGKey(raw string) error {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil || len(b) != 32 {
		return errors.New("必须是 32 字节标准 Base64 密钥")
	}
	return nil
}

func parseCIDRList(raw string) ([]string, error) {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}
		if prefix, err := netip.ParsePrefix(item); err == nil {
			out = append(out, prefix.String())
			continue
		}
		if addr, err := netip.ParseAddr(item); err == nil {
			out = append(out, netip.PrefixFrom(addr, addr.BitLen()).String())
			continue
		}
		return nil, fmt.Errorf("无效网段或 IP %q", item)
	}
	if len(out) == 0 {
		return nil, errors.New("至少需要一个网段或 IP")
	}
	return out, nil
}

func parseIPList(raw string) ([]string, error) {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}
		addr, err := netip.ParseAddr(item)
		if err != nil {
			return nil, fmt.Errorf("DNS 必须是有效 IP 地址，收到 %q", item)
		}
		out = append(out, addr.String())
	}
	return out, nil
}

func validateEndpoint(raw string) (string, error) {
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(raw))
	if err != nil || host == "" || portStr == "" {
		return "", errors.New("必须为 host:port 格式")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("端口必须在 1~65535 之间")
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return net.JoinHostPort(addr.String(), portStr), nil
	}
	if !isSafeHostname(host) {
		return "", errors.New("主机名包含非法字符")
	}
	return net.JoinHostPort(host, portStr), nil
}

func isSafeHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		isValid := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_'
		if !isValid {
			return false
		}
	}
	return true
}
