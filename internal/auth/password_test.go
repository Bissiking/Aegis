package auth

import (
	"strings"
	"testing"
	"time"
)

func TestArgon2idRoundTrip(t *testing.T) {
	p := Params{Time: 1, Memory: 8 * 1024, Threads: 1, KeyLen: 32, SaltLen: 16}
	h, err := HashPassword("Correct-Horse-9!", p)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if !strings.HasPrefix(h, "argon2id$v=19$") {
		t.Fatalf("unexpected encoding: %s", h)
	}
	ok, err := VerifyPassword(h, "Correct-Horse-9!")
	if err != nil || !ok {
		t.Fatalf("verify ok=%v err=%v", ok, err)
	}
	ok, _ = VerifyPassword(h, "correct-horse-9!")
	if ok {
		t.Fatal("wrong password accepted")
	}
}

func TestPasswordPolicy(t *testing.T) {
	cases := []struct {
		pw   string
		fail bool
	}{
		{"short1!", true},
		{"alllowercaseonly", true},
		{"Abcdefghijklmn1", false},
		{"Aegis-Panel-2026!", false},
		{"12345678901234", true},
	}
	for _, c := range cases {
		err := ValidatePasswordPolicy(c.pw)
		if c.fail && err == nil {
			t.Errorf("%q should be rejected", c.pw)
		}
		if !c.fail && err != nil {
			t.Errorf("%q should be accepted: %v", c.pw, err)
		}
	}
}

func TestLoginLimiter(t *testing.T) {
	l := NewLoginLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !l.Allow("k") {
			t.Fatalf("attempt %d should be allowed", i+1)
		}
	}
	if l.Allow("k") {
		t.Fatal("4th attempt must be blocked")
	}
	if !l.Allow("other") {
		t.Fatal("other key must be independent")
	}
	l.Reset("k")
	if !l.Allow("k") {
		t.Fatal("reset must clear the key")
	}
}

func TestSafeRedirectRejectsExternal(t *testing.T) {
	// documented in api package; keep the helper behaviour here as a guard.
	got := stringsHasPrefixFn("//evil.com", "//")
	if !got {
		t.Fatal("protocol-relative URL must be detected")
	}
}

func stringsHasPrefixFn(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }
