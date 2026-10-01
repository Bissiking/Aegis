package service

import (
	"net"
	"strings"

	"github.com/aegis-vpn/aegis/internal/wg"
)

// wgValidateServer checks a server payload before it reaches persistence.
func wgValidateServer(in ServerInput) error {
	if err := wg.ValidateInterface(in.WGInterface); err != nil {
		return &FieldError{Field: "wg_interface"}
	}
	if in.WGPort < 1 || in.WGPort > 65535 {
		return &FieldError{Field: "wg_port"}
	}
	if _, _, err := net.ParseCIDR(in.VPNCIDR); err != nil {
		return &FieldError{Field: "vpn_cidr"}
	}
	for _, d := range splitCSV(in.DNS) {
		if net.ParseIP(d) == nil {
			return &FieldError{Field: "dns"}
		}
	}
	if in.MaxPeers < 0 || in.MaxPeers > 100000 {
		return &FieldError{Field: "max_peers"}
	}
	if in.ProfileTTLHours < 0 || in.ProfileTTLHours > 87600 {
		return &FieldError{Field: "profile_ttl_hours"}
	}
	if strings.ContainsAny(in.EndpointPublic, " \t\r\n") {
		return &FieldError{Field: "endpoint_public"}
	}
	return nil
}

// ValidateRegistrationInput guards the device creation payload.
func ValidateDeviceName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 {
		return &FieldError{Field: "name"}
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return &FieldError{Field: "name"}
		}
	}
	return nil
}
