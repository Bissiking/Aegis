// Package auth implements authentication primitives for Aegis: Argon2id
// password hashing, server-side sessions, CSRF, login throttling and a generic
// native Kyros SSO v4 adapter.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters embedded in each hash string.
type Params struct {
	Time    uint32
	Memory  uint32 // KiB
	Threads uint8
	KeyLen  uint32
	SaltLen uint32
}

// DefaultParams follows the OWASP Argon2id recommendation (64 MiB, t=3, p=2).
var DefaultParams = Params{Time: 3, Memory: 65536, Threads: 2, KeyLen: 32, SaltLen: 16}

// ErrPasswordPolicy is returned when a password does not meet the policy.
var ErrPasswordPolicy = errors.New("password does not meet the policy")

// HashPassword produces an encoded Argon2id hash:
// argon2id$v=19$m=..,t=..,p=..$salt$hash
func HashPassword(password string, p Params) (string, error) {
	if err := ValidatePasswordPolicy(password); err != nil {
		return "", err
	}
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	return fmt.Sprintf("argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		p.Memory, p.Time, p.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword checks a password against an encoded hash in constant time.
func VerifyPassword(encoded, password string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "argon2id" {
		return false, fmt.Errorf("unsupported hash format")
	}
	var mem, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[2], "m=%d,t=%d,p=%d", &mem, &t, &p); err != nil {
		return false, fmt.Errorf("invalid hash parameters")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false, fmt.Errorf("invalid salt")
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("invalid digest")
	}
	got := argon2.IDKey([]byte(password), salt, t, mem, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// ValidatePasswordPolicy enforces a reasonable local password policy.
func ValidatePasswordPolicy(password string) error {
	if len(password) < 12 {
		return fmt.Errorf("%w: at least 12 characters", ErrPasswordPolicy)
	}
	if len(password) > 256 {
		return fmt.Errorf("%w: at most 256 characters", ErrPasswordPolicy)
	}
	var hasLower, hasUpper, hasDigit, hasSymbol bool
	for _, r := range password {
		switch {
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= '0' && r <= '9':
			hasDigit = true
		default:
			hasSymbol = true
		}
	}
	classes := 0
	for _, ok := range []bool{hasLower, hasUpper, hasDigit, hasSymbol} {
		if ok {
			classes++
		}
	}
	if classes < 3 {
		return fmt.Errorf("%w: use at least 3 of {lowercase, uppercase, digits, symbols}", ErrPasswordPolicy)
	}
	switch strings.ToLower(password) {
	case "password1234", "administrator", "changeme1234":
		return fmt.Errorf("%w: password is too common", ErrPasswordPolicy)
	}
	return nil
}
