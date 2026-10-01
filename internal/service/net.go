package service

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/aegis-vpn/aegis/internal/wg"
)

// errNoEgress is returned when the outbound interface cannot be determined.
var errNoEgress = fmt.Errorf("outbound interface unknown: set AEGIS_WG_EGRESS_IFACE")

// egressInterface resolves the interface carrying Internet traffic, used to
// build the MASQUERADE rule. An explicit configuration always wins; otherwise
// the default IPv4 route is read from the kernel routing table.
func egressInterface(configured string) (string, error) {
	if configured != "" {
		if err := wg.ValidateInterface(configured); err != nil {
			return "", fmt.Errorf("invalid egress interface: %w", err)
		}
		return configured, nil
	}
	if iface, ok := defaultRouteIface("/proc/net/route"); ok {
		return iface, nil
	}
	return "", errNoEgress
}

// defaultRouteIface parses /proc/net/route looking for the default route.
func defaultRouteIface(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if i == 0 {
			continue // header
		}
		f := strings.Fields(line)
		if len(f) < 4 || f[1] != "00000000" {
			continue // destination != default route
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil || flags&0x1 == 0 {
			continue // interface must be UP
		}
		if err := wg.ValidateInterface(f[0]); err != nil {
			continue
		}
		return f[0], true
	}
	return "", false
}

// allocateIP returns a free host address inside cidr, avoiding the network,
// broadcast and gateway addresses plus the entries in `used`.
func allocateIP(cidr string, used map[string]bool) (string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("invalid vpn cidr: %w", err)
	}
	ip := ipNet.IP.To4()
	if ip == nil {
		return "", fmt.Errorf("only IPv4 vpn networks are supported by the MVP")
	}
	ones, bits := ipNet.Mask.Size()
	if bits != 32 {
		return "", fmt.Errorf("invalid mask")
	}
	hostBits := bits - ones
	if hostBits < 2 {
		return "", fmt.Errorf("vpn network is too small")
	}
	total := 1 << uint(hostBits)
	if total > 65536 {
		total = 65536 // safety bound
	}
	base := ip.Mask(ipNet.Mask).To4()
	if base == nil {
		return "", fmt.Errorf("invalid network base")
	}
	for off := 1; off < total-1; off++ {
		cand := make(net.IP, 4)
		copy(cand, base)
		addHost(cand, off)
		if !ipNet.Contains(cand) {
			continue
		}
		if off == 1 {
			continue // reserved for the server interface address
		}
		cidrAddr := cand.String() + "/32"
		if used[cidrAddr] {
			continue
		}
		return cidrAddr, nil
	}
	return "", fmt.Errorf("no free address left in %s", cidr)
}

func addHost(ip net.IP, offset int) {
	v := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
	v += uint32(offset)
	ip[0] = byte(v >> 24)
	ip[1] = byte(v >> 16)
	ip[2] = byte(v >> 8)
	ip[3] = byte(v)
}

// interfaceAddress returns the host address of the WireGuard interface (/32).
func interfaceAddress(cidr string) (string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}
	ip := ipNet.IP.To4()
	if ip == nil {
		return "", fmt.Errorf("only IPv4 vpn networks are supported by the MVP")
	}
	base := ip.Mask(ipNet.Mask).To4()
	if base == nil {
		return "", fmt.Errorf("invalid network base")
	}
	out := make(net.IP, 4)
	copy(out, base)
	addHost(out, 1)
	return out.String() + "/32", nil
}
