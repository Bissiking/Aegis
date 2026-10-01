package wg

import (
	"encoding/base64"
	"testing"
)

// validKey returns a syntactically correct 32-byte WireGuard public key.
func validKey() string {
	return base64.StdEncoding.EncodeToString(make([]byte, 32))
}

func TestValidateInterfaceRejectsInjection(t *testing.T) {
	bad := []string{
		"", "wg0; rm -rf /", "wg0 && whoami", "wg0`id`", "a b", "wg0\n",
		"../../etc/passwd", "verylonginterfacename",
	}
	for _, v := range bad {
		if err := ValidateInterface(v); err == nil {
			t.Errorf("interface %q must be rejected", v)
		}
	}
	for _, ok := range []string{"wg0", "wg1", "a"} {
		if err := ValidateInterface(ok); err != nil {
			t.Errorf("interface %q must be accepted: %v", ok, err)
		}
	}
}

func TestValidatePublicKeyRejectsGarbage(t *testing.T) {
	bad := []string{"", "abc", "not base64 !!!", "A==", "wg0; reboot"}
	for _, v := range bad {
		if err := ValidatePublicKey(v); err == nil {
			t.Errorf("public key %q must be rejected", v)
		}
	}
	good := validKey()
	if err := ValidatePublicKey(good); err != nil {
		t.Errorf("valid key rejected: %v", err)
	}
}

func TestValidateAllowedIPRejectsNonHostCIDR(t *testing.T) {
	bad := []string{
		"", "10.77.0.0/24,10.77.0.1/32", "0.0.0.0/0", "10.77.0.1", "10.77.0.1/32; cat /etc/shadow",
	}
	for _, v := range bad {
		if err := ValidateAllowedIP(v); err == nil {
			t.Errorf("allowed-ip %q must be rejected", v)
		}
	}
	if err := ValidateAllowedIP("10.77.0.5/32"); err != nil {
		t.Errorf("valid host cidr rejected: %v", err)
	}
}

func TestBuiltinCommandAllowlist(t *testing.T) {
	good := []string{
		"sysctl -w net.ipv4.ip_forward=1",
		"iptables -t nat -A POSTROUTING -s 10.77.0.0/24 -o eth0 -j MASQUERADE",
	}
	for _, g := range good {
		if err := validateBuiltinNetCommand(g); err != nil {
			t.Errorf("expected %q to be allowed: %v", g, err)
		}
	}
	bad := []string{
		"iptables -j $(reboot)",
		"sh -c 'id'",
		"rm -rf /",
		"iptables -A FOO; curl evil",
		"echo pwned",
	}
	for _, b := range bad {
		if err := validateBuiltinNetCommand(b); err == nil {
			t.Errorf("expected %q to be rejected", b)
		}
	}
}

func TestRequestValidationIsClosedSet(t *testing.T) {
	cases := []Request{
		{Op: "rm_rf", Interface: "wg0"},
		{Op: OpAddPeer, Interface: "wg0; reboot", PublicKey: validKey(), AllowedIP: "10.77.0.2/32"},
		{Op: OpSyncConfig, Config: nil},
		{Op: OpRateLimit, Interface: "wg0", PublicKey: validKey(), AllowedIP: "10.77.0.2/32", UpKbps: -5},
	}
	for i, c := range cases {
		if err := c.Validate(); err == nil {
			t.Errorf("case %d must be rejected", i)
		}
	}
	valid := Request{
		Op: OpRemovePeer, Interface: "wg0",
		PublicKey: validKey(),
	}
	if err := valid.Validate(); err != nil {
		t.Errorf("valid request rejected: %v", err)
	}
}

func TestSyncConfigRejectsHostilePayload(t *testing.T) {
	cfg := PersistentConfig{
		Interface:  "wg0",
		ListenPort: 51820,
		Address:    "10.77.0.1/24",
		PostUp:     []string{"iptables -A FORWARD -j $(curl evil)"},
	}
	if err := validatePersistentConfig(&cfg); err == nil {
		t.Fatal("hostile PostUp must be rejected")
	}
	cfg.PostUp = []string{"iptables -A FORWARD -j ACCEPT"}
	cfg.Peers = []ConfigPeer{{PublicKey: "nope", AllowedIPs: []string{"0.0.0.0/0"}}}
	if err := validatePersistentConfig(&cfg); err == nil {
		t.Fatal("invalid peer must be rejected")
	}
}
