package ctfrunner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const sampleTPCTFConf = `[Interface]
PrivateKey = YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=
Address = 172.17.112.254/32
DNS = 172.17.112.3, 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=
Endpoint = node7.tpctf.ctfy.run:44749
AllowedIPs = 172.17.112.0/24
PersistentKeepalive = 25
`

func TestParseWireGuardConfigSample(t *testing.T) {
	prof, err := ParseWireGuardConfig(sampleTPCTFConf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if prof.Hash == "" || len(prof.Hash) != 64 {
		t.Fatalf("unexpected hash: %q", prof.Hash)
	}
	if prof.Address != "172.17.112.254/32" {
		t.Fatalf("unexpected address: %q", prof.Address)
	}
	if prof.Endpoint != "node7.tpctf.ctfy.run:44749" {
		t.Fatalf("unexpected endpoint: %q", prof.Endpoint)
	}
	if len(prof.DNS) != 3 || prof.DNS[0] != "172.17.112.3" {
		t.Fatalf("unexpected DNS: %+v", prof.DNS)
	}
	if len(prof.AllowedIPs) != 1 || prof.AllowedIPs[0] != "172.17.112.0/24" {
		t.Fatalf("unexpected AllowedIPs: %+v", prof.AllowedIPs)
	}
	if prof.PersistentKeepalive != 25 {
		t.Fatalf("unexpected keepalive: %d", prof.PersistentKeepalive)
	}
	if strings.Contains(prof.RunnerConfig, "DNS =") {
		t.Fatalf("runner config should strip DNS for container wg-quick compatibility:\n%s", prof.RunnerConfig)
	}
	roundtrip, err := ParseWireGuardConfig(prof.RawSanitized)
	if err != nil || roundtrip.Hash != prof.Hash {
		t.Fatalf("roundtrip hash mismatch: %v %q != %q", err, roundtrip.Hash, prof.Hash)
	}
	summary := prof.Summary("ctfy-40099377a2.conf")
	if !summary.Enabled || summary.Filename != "ctfy-40099377a2.conf" || summary.Endpoint != prof.Endpoint {
		t.Fatalf("unexpected summary: %+v", summary)
	}
}

func TestParseWireGuardConfigRejectsDangerousHooks(t *testing.T) {
	cases := []struct {
		name string
		conf string
	}{
		{
			name: "PostUp",
			conf: sampleTPCTFConf + "\n[Interface]\n",
		},
		{
			name: "PostUpInInterface",
			conf: strings.Replace(sampleTPCTFConf, "DNS = 172.17.112.3, 1.1.1.1, 8.8.8.8", "PostUp = id > /tmp/pwn", 1),
		},
		{
			name: "PreUpInPeer",
			conf: sampleTPCTFConf + "PreUp = curl attacker\n",
		},
		{
			name: "BadDNSOptionInjection",
			conf: strings.Replace(sampleTPCTFConf, "DNS = 172.17.112.3, 1.1.1.1, 8.8.8.8", "DNS = 1.1.1.1\\noptions ndots:0", 1),
		},
		{
			name: "InvalidKey",
			conf: strings.Replace(sampleTPCTFConf, "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=", "not-a-key", 1),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseWireGuardConfig(tc.conf); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

const sampleOpenVPNConf = `client
dev tun
proto udp
remote vpn.tsecbench.example 1194
resolv-retry infinite
nobind
user nobody
group nogroup
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
script-security 2
up /etc/openvpn/update-resolv-conf
down /etc/openvpn/update-resolv-conf
dhcp-option DNS 10.8.0.2
dhcp-option DNS 1.1.1.1
route 10.66.0.0 255.255.0.0
verb 3
<ca>
-----BEGIN CERTIFICATE-----
MIIBFAKECA==
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
MIIBFAKECERT==
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
MIIBFAKEKEY==
-----END PRIVATE KEY-----
</key>
<tls-crypt>
-----BEGIN OpenVPN Static key V1-----
00112233445566778899aabbccddeeff
-----END OpenVPN Static key V1-----
</tls-crypt>
`

func TestParseOpenVPNConfigSampleAndDetect(t *testing.T) {
	if got := DetectVPNKind(sampleTPCTFConf); got != VPNKindWireGuard {
		t.Fatalf("expected wireguard detect, got %q", got)
	}
	if got := DetectVPNKind(sampleOpenVPNConf); got != VPNKindOpenVPN {
		t.Fatalf("expected openvpn detect, got %q", got)
	}

	prof, err := ParseVPNConfig(sampleOpenVPNConf)
	if err != nil {
		t.Fatalf("ParseVPNConfig failed: %v", err)
	}
	if prof.Kind != VPNKindOpenVPN {
		t.Fatalf("expected Kind=%s, got %q", VPNKindOpenVPN, prof.Kind)
	}
	if prof.Proto != "udp" {
		t.Fatalf("expected proto udp, got %q", prof.Proto)
	}
	if prof.Endpoint != "vpn.tsecbench.example:1194" {
		t.Fatalf("unexpected endpoint: %q", prof.Endpoint)
	}
	if len(prof.DNS) != 2 || prof.DNS[0] != "10.8.0.2" {
		t.Fatalf("unexpected DNS: %+v", prof.DNS)
	}
	if len(prof.AllowedIPs) != 1 || prof.AllowedIPs[0] != "10.66.0.0/255.255.0.0" {
		t.Fatalf("unexpected routes: %+v", prof.AllowedIPs)
	}
	if strings.Contains(prof.RawSanitized, "update-resolv-conf") ||
		strings.Contains(prof.RawSanitized, "script-security") ||
		strings.Contains(prof.RawSanitized, "user nobody") ||
		strings.Contains(prof.RawSanitized, "group nogroup") {
		t.Fatalf("expected benign boilerplate directives stripped, got:\n%s", prof.RawSanitized)
	}
	if !strings.Contains(prof.RunnerConfig, "<tls-crypt>") {
		t.Fatalf("expected inline <tls-crypt> preserved")
	}

	summary := prof.Summary("task_202611klci1w5y69_vpn_config.ovpn")
	if !summary.Enabled || summary.Kind != VPNKindOpenVPN || summary.Proto != "udp" || summary.Filename != "task_202611klci1w5y69_vpn_config.ovpn" {
		t.Fatalf("unexpected openvpn summary: %+v", summary)
	}
}

func TestParseOpenVPNConfigRejectsUnsafeDirectives(t *testing.T) {
	cases := []struct {
		name string
		conf string
	}{
		{
			name: "CustomUpScript",
			conf: strings.Replace(sampleOpenVPNConf, "up /etc/openvpn/update-resolv-conf", "up /tmp/pwn.sh", 1),
		},
		{
			name: "Plugin",
			conf: sampleOpenVPNConf + "\nplugin /tmp/evil.so\n",
		},
		{
			name: "ExternalCAPath",
			conf: sampleOpenVPNConf + "\nca /etc/passwd\n",
		},
		{
			name: "ScriptSecurity3",
			conf: strings.Replace(sampleOpenVPNConf, "script-security 2", "script-security 3", 1),
		},
		{
			name: "MissingRemote",
			conf: strings.Replace(sampleOpenVPNConf, "remote vpn.tsecbench.example 1194", "", 1),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseOpenVPNConfig(tc.conf); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

func TestEnsureVPNNetworkOverlapsFallback(t *testing.T) {
	var seenSubnets []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/networks/"):
			http.Error(w, `{"message":"network not found"}`, http.StatusNotFound)
		case r.Method == http.MethodPost && r.URL.Path == "/networks/create":
			var body struct {
				IPAM struct {
					Config []struct {
						Subnet string `json:"Subnet"`
					} `json:"Config"`
				} `json:"IPAM"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			subnet := ""
			if len(body.IPAM.Config) > 0 {
				subnet = body.IPAM.Config[0].Subnet
			}
			seenSubnets = append(seenSubnets, subnet)
			if subnet == "10.220.0.0/16" {
				http.Error(w, `{"message":"invalid pool request: Pool overlaps with other one on this address space"}`, http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"Id":"net-1"}`))
		default:
			http.Error(w, "unexpected request", http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	t.Setenv("P3Y_VPN_SUBNET", "10.220.0.0/16")
	e := &Engine{Client: srv.Client(), Base: srv.URL}
	if err := e.EnsureVPNNetwork(context.Background()); err != nil {
		t.Fatalf("EnsureVPNNetwork failed: %v", err)
	}
	if len(seenSubnets) != 2 || seenSubnets[0] != "10.220.0.0/16" || seenSubnets[1] != "10.221.0.0/16" {
		t.Fatalf("unexpected subnet fallback sequence: %+v", seenSubnets)
	}
}
