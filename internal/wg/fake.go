package wg

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Fake is an in-memory implementation of Client used by the test suite so that
// no root privileges and no real WireGuard interface are required.
type Fake struct {
	mu        sync.Mutex
	ifaces    map[string]map[string]string // iface -> pubkey -> allowedIP
	limits    map[string][2]int            // pubkey -> [up,down]
	configs   []PersistentConfig
	syncCount int

	// Hooks allow tests to simulate failures and counter resets.
	FailAdd   error
	FailRead  error
	StateHook func(iface string, s *State)

	clock func() time.Time
}

// NewFake returns an empty fake.
func NewFake() *Fake {
	return &Fake{
		ifaces: map[string]map[string]string{},
		limits: map[string][2]int{},
		clock:  time.Now,
	}
}

// SetClock overrides the fake clock (tests only).
func (f *Fake) SetClock(fn func() time.Time) { f.clock = fn }

func (f *Fake) iface(name string) map[string]string {
	if f.ifaces[name] == nil {
		f.ifaces[name] = map[string]string{}
	}
	return f.ifaces[name]
}

// AddPeer implements Client.
func (f *Fake) AddPeer(_ context.Context, iface, publicKey, allowedIP string) error {
	if f.FailAdd != nil {
		return f.FailAdd
	}
	if err := ValidateInterface(iface); err != nil {
		return err
	}
	if err := ValidatePublicKey(publicKey); err != nil {
		return err
	}
	if err := ValidateAllowedIP(allowedIP); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.iface(iface)[publicKey] = allowedIP
	return nil
}

// ModifyPeer implements Client.
func (f *Fake) ModifyPeer(ctx context.Context, iface, publicKey, allowedIP string) error {
	if err := f.AddPeer(ctx, iface, publicKey, allowedIP); err != nil {
		return err
	}
	return nil
}

// RemovePeer implements Client.
func (f *Fake) RemovePeer(_ context.Context, iface, publicKey string) error {
	if err := ValidateInterface(iface); err != nil {
		return err
	}
	if err := ValidatePublicKey(publicKey); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.iface(iface), publicKey)
	delete(f.limits, publicKey)
	return nil
}

// ReadState implements Client.
func (f *Fake) ReadState(_ context.Context, iface string) (*State, error) {
	if f.FailRead != nil {
		return nil, f.FailRead
	}
	if err := ValidateInterface(iface); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	st := &State{Interface: iface, ListenPort: 51820, CollectedAt: f.clock()}
	for pk, ip := range f.iface(iface) {
		st.Peers = append(st.Peers, PeerState{
			PublicKey:       pk,
			AllowedIPs:      []string{ip},
			LastHandshakeAt: time.Time{},
		})
	}
	if f.StateHook != nil {
		f.StateHook(iface, st)
	}
	return st, nil
}

// ApplyRateLimit implements Client.
func (f *Fake) ApplyRateLimit(_ context.Context, _ string, publicKey string, _ string, up, down int) error {
	if err := ValidateRateLimits(up, down); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.limits[publicKey] = [2]int{up, down}
	return nil
}

// SyncConfig implements Client.
func (f *Fake) SyncConfig(_ context.Context, cfg PersistentConfig) error {
	if err := validatePersistentConfig(&cfg); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.syncCount++
	f.configs = append(f.configs, cfg)
	return nil
}

// HasPeer reports whether a peer exists on an interface.
func (f *Fake) HasPeer(iface, publicKey string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.iface(iface)[publicKey]
	return ok
}

// PeersOn returns a copy of the peers of an interface.
func (f *Fake) PeersOn(iface string) map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]string{}
	for k, v := range f.iface(iface) {
		out[k] = v
	}
	return out
}

// LastConfig returns the most recent persisted configuration.
func (f *Fake) LastConfig() (PersistentConfig, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.configs) == 0 {
		return PersistentConfig{}, fmt.Errorf("no config synced yet")
	}
	return f.configs[len(f.configs)-1], nil
}

// SyncCount returns how many times SyncConfig was called.
func (f *Fake) SyncCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.syncCount
}

// Limit returns the shaping values applied to a peer.
func (f *Fake) Limit(publicKey string) (up, down int, ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.limits[publicKey]
	return v[0], v[1], ok
}
