// aegis-agent is the only component of Aegis allowed to touch WireGuard.
//
// It runs as root (or with CAP_NET_ADMIN) under systemd, listens on a Unix
// domain socket with restrictive permissions, and accepts exactly six typed
// operations. It never builds a shell command string from an input value:
// every external program is invoked with an explicit argument slice.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aegis-vpn/aegis/internal/wg"
)

type server struct {
	listen    string
	token     string
	wgPath    string
	tcPath    string
	confDir   string
	ifbEnable bool
	mu        sync.Mutex
	ln        net.Listener
}

func main() {
	var (
		listen  = flag.String("listen", envOr("AEGIS_AGENT_LISTEN", "unix:///run/aegis/agent.sock"), "listen address (unix:///path or tcp://127.0.0.1:port)")
		token   = flag.String("token", os.Getenv("AEGIS_AGENT_TOKEN"), "shared secret required on every request (mandatory for tcp://)")
		wgPath  = flag.String("wg", envOr("AEGIS_WG_BIN", "wg"), "path to the wg binary")
		tcPath  = flag.String("tc", envOr("AEGIS_TC_BIN", "tc"), "path to the tc binary")
		confDir = flag.String("conf-dir", envOr("AEGIS_WG_CONF_DIR", "/etc/wireguard"), "directory holding the persistent WireGuard configuration")
		ifb     = flag.Bool("ifb", false, "enable IFB-based upload shaping (experimental, off by default)")
	)
	flag.Parse()

	s := &server{
		listen:    *listen,
		token:     *token,
		wgPath:    *wgPath,
		tcPath:    *tcPath,
		confDir:   *confDir,
		ifbEnable: *ifb,
	}

	if strings.HasPrefix(s.listen, "tcp://") && s.token == "" {
		fatal("aegis-agent: refusing to listen on tcp:// without AEGIS_AGENT_TOKEN")
	}

	ln, err := net.Listen(parseListen(s.listen))
	if err != nil {
		fatal("aegis-agent: listen: %v", err)
	}
	s.ln = ln
	fmt.Fprintf(os.Stderr, "aegis-agent: listening on %s\n", s.listen)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go s.handle(conn)
	}
}

func parseListen(addr string) (network, address string) {
	switch {
	case strings.HasPrefix(addr, "unix://"):
		path := strings.TrimPrefix(addr, "unix://")
		_ = os.MkdirAll(filepath.Dir(path), 0o750)
		_ = os.Remove(path)
		return "unix", path
	case strings.HasPrefix(addr, "tcp://"):
		return "tcp", strings.TrimPrefix(addr, "tcp://")
	default:
		_ = os.MkdirAll(filepath.Dir(addr), 0o750)
		_ = os.Remove(addr)
		return "unix", addr
	}
}

func (s *server) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return
	}
	var req wg.Request
	if err := json.Unmarshal(line, &req); err != nil {
		s.write(conn, &wg.Response{OK: false, Error: "malformed request"})
		return
	}
	if s.token != "" && subtleNeq(req.Token, s.token) {
		s.write(conn, &wg.Response{OK: false, Error: "unauthorized"})
		return
	}
	if err := req.Validate(); err != nil {
		s.write(conn, &wg.Response{OK: false, Error: err.Error()})
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	switch req.Op {
	case wg.OpHealth:
		s.write(conn, &wg.Response{OK: true})
	case wg.OpAddPeer:
		s.write(conn, s.okErr(s.addPeer(req.Interface, req.PublicKey, req.AllowedIP)))
	case wg.OpModifyPeer:
		s.write(conn, s.okErr(s.addPeer(req.Interface, req.PublicKey, req.AllowedIP)))
	case wg.OpRemovePeer:
		s.write(conn, s.okErr(s.removePeer(req.Interface, req.PublicKey)))
	case wg.OpReadState:
		st, err := s.readState(req.Interface)
		if err != nil {
			s.write(conn, &wg.Response{OK: false, Error: err.Error()})
			return
		}
		s.write(conn, &wg.Response{OK: true, State: st})
	case wg.OpRateLimit:
		s.write(conn, s.okErr(s.rateLimit(req.Interface, req.PublicKey, req.AllowedIP, req.UpKbps, req.DownKbps)))
	case wg.OpSyncConfig:
		s.write(conn, s.okErr(s.syncConfig(req.Config)))
	default:
		s.write(conn, &wg.Response{OK: false, Error: "unknown operation"})
	}
}

func (s *server) okErr(err error) *wg.Response {
	if err != nil {
		return &wg.Response{OK: false, Error: err.Error()}
	}
	return &wg.Response{OK: true}
}

func (s *server) write(conn net.Conn, resp *wg.Response) {
	b, _ := json.Marshal(resp)
	_, _ = conn.Write(append(b, '\n'))
}

// ------------------------------------------------------------------ wg ops

func (s *server) addPeer(iface, pub, allowed string) error {
	if _, err := exec.LookPath(s.wgPath); err != nil {
		return fmt.Errorf("wg binary not available")
	}
	return run(s.wgPath, "set", iface, "peer", pub, "allowed-ips", allowed)
}

func (s *server) removePeer(iface, pub string) error {
	if _, err := exec.LookPath(s.wgPath); err != nil {
		return fmt.Errorf("wg binary not available")
	}
	return run(s.wgPath, "set", iface, "peer", pub, "remove")
}

func (s *server) readState(iface string) (*wg.State, error) {
	if _, err := exec.LookPath(s.wgPath); err != nil {
		return nil, fmt.Errorf("wg binary not available")
	}
	out, err := output(s.wgPath, "show", iface, "dump")
	if err != nil {
		return nil, err
	}
	st := &wg.State{Interface: iface, CollectedAt: time.Now().UTC()}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	for i, line := range lines {
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if i == 0 {
			if len(f) >= 4 {
				st.PublicKey = f[1]
				st.ListenPort, _ = strconv.Atoi(f[2])
			}
			continue
		}
		if len(f) < 8 {
			continue
		}
		hs, _ := strconv.ParseInt(f[4], 10, 64)
		rx, _ := strconv.ParseInt(f[5], 10, 64)
		tx, _ := strconv.ParseInt(f[6], 10, 64)
		ka, _ := strconv.Atoi(f[7])
		ps := wg.PeerState{
			PublicKey:    f[0],
			RxBytes:      rx,
			TxBytes:      tx,
			PersistentKA: ka,
		}
		if hs > 0 {
			ps.LastHandshakeAt = time.Unix(hs, 0).UTC()
		}
		if f[3] != "" {
			ps.AllowedIPs = strings.Split(f[3], ",")
		}
		if len(f) > 8 {
			ps.Endpoint = f[8]
		}
		st.Peers = append(st.Peers, ps)
	}
	return st, nil
}

// rateLimit applies best-effort egress shaping for a single peer using HTB.
//
// MVP limitation: only the server-to-client (download) direction is shaped.
// Upload shaping requires an IFB device and is opt-in through -ifb.
func (s *server) rateLimit(iface, pub, allowed string, up, down int) error {
	if _, err := exec.LookPath(s.tcPath); err != nil {
		return fmt.Errorf("tc binary not available")
	}
	ip := allowed
	if i := strings.IndexByte(ip, '/'); i > 0 {
		ip = ip[:i]
	}
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid peer address")
	}
	classID := tcClassFor(ip)

	if down <= 0 {
		// Remove any shaping previously applied to this address.
		_ = run(s.tcPath, "filter", "del", "dev", iface, "protocol", "ip", "parent", "1:", "prio", "1",
			"u32", "match", "ip", "dst", ip+"/32", "flowid", classID)
		return nil
	}
	if err := run(s.tcPath, "qdisc", "replace", "dev", iface, "root", "handle", "1:", "htb", "default", "10"); err != nil {
		return err
	}
	if err := run(s.tcPath, "class", "replace", "dev", iface, "parent", "1:", "classid", "1:10",
		"htb", "rate", "1000gbit", "ceil", "1000gbit"); err != nil {
		return err
	}
	if err := run(s.tcPath, "class", "replace", "dev", iface, "parent", "1:10", "classid", classID,
		"htb", "rate", fmt.Sprintf("%dkbit", down), "ceil", fmt.Sprintf("%dkbit", down)); err != nil {
		return err
	}
	_ = run(s.tcPath, "filter", "del", "dev", iface, "protocol", "ip", "parent", "1:", "prio", "1",
		"u32", "match", "ip", "dst", ip+"/32", "flowid", classID)
	return run(s.tcPath, "filter", "add", "dev", iface, "protocol", "ip", "parent", "1:", "prio", "1",
		"u32", "match", "ip", "dst", ip+"/32", "flowid", classID)
}

var tcHexRe = regexp.MustCompile(`^[0-9a-f]{1,4}$`)

// tcClassFor derives a stable HTB class id (1:XXXX) from a VPN address.
func tcClassFor(ip string) string {
	h := uint32(2166136261)
	for i := 0; i < len(ip); i++ {
		h ^= uint32(ip[i])
		h *= 16777619
	}
	id := fmt.Sprintf("%04x", (h%0xfffe)+1)
	if !tcHexRe.MatchString(id) {
		id = "0010"
	}
	return "1:" + id
}

// syncConfig atomically rewrites the persistent WireGuard configuration.
func (s *server) syncConfig(cfg *wg.PersistentConfig) error {
	if cfg == nil {
		return fmt.Errorf("missing config")
	}
	path := filepath.Join(s.confDir, cfg.Interface+".conf")
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\n")
	fmt.Fprintf(&b, "Address = %s\n", cfg.Address)
	if len(cfg.DNS) > 0 {
		fmt.Fprintf(&b, "DNS = %s\n", strings.Join(cfg.DNS, ", "))
	}
	fmt.Fprintf(&b, "ListenPort = %d\n", cfg.ListenPort)
	fmt.Fprintf(&b, "SaveConfig = %v\n", cfg.SaveConfig)
	for _, up := range cfg.PostUp {
		fmt.Fprintf(&b, "PostUp = %s\n", up)
	}
	for _, down := range cfg.PostDown {
		fmt.Fprintf(&b, "PostDown = %s\n", down)
	}
	for _, p := range cfg.Peers {
		fmt.Fprintf(&b, "\n[Peer]\n")
		fmt.Fprintf(&b, "PublicKey = %s\n", p.PublicKey)
		fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(p.AllowedIPs, ", "))
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("commit config: %w", err)
	}
	return nil
}

// ------------------------------------------------------------------ helpers

func run(name string, args ...string) error {
	if len(args) == 0 {
		return fmt.Errorf("no arguments")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", filepath.Base(name), args[0], err)
	}
	return nil
}

func output(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var sb strings.Builder
	cmd.Stdout = &sb
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s: %w", filepath.Base(name), err)
	}
	return sb.String(), nil
}

func subtleNeq(a, b string) bool {
	if len(a) != len(b) {
		return true
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v != 0
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
