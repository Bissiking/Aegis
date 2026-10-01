// Package wgkeys provides WireGuard key generation and encoding.
//
// Only public keys are ever persisted by Aegis. Private keys are produced
// transiently for a single profile delivery and are discarded immediately
// afterwards; they are never written to the database, logs or error payloads.
package wgkeys

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// KeySize is the size of a WireGuard key in bytes.
const KeySize = 32

// KeyPair holds a WireGuard private/public key pair in raw bytes.
type KeyPair struct {
	Private [KeySize]byte
	Public  [KeySize]byte
}

// Generate creates a new key pair using a cryptographically secure source.
func Generate() (KeyPair, error) {
	var kp KeyPair
	if _, err := rand.Read(kp.Private[:]); err != nil {
		return KeyPair{}, fmt.Errorf("secure random: %w", err)
	}
	// Clamp as required by X25519 (same as the reference implementation).
	kp.Private[0] &= 248
	kp.Private[31] &= 127
	kp.Private[31] |= 64

	pub, err := curve25519.X25519(kp.Private[:], curve25519.Basepoint)
	if err != nil {
		return KeyPair{}, fmt.Errorf("derive public key: %w", err)
	}
	copy(kp.Public[:], pub)
	return kp, nil
}

// EncodePrivate base64-encodes a private key. Callers must treat the result as
// a secret: it must never be persisted or logged.
func (k *KeyPair) EncodePrivate() string {
	return base64.StdEncoding.EncodeToString(k.Private[:])
}

// EncodePublic base64-encodes a public key.
func (k *KeyPair) EncodePublic() string {
	return base64.StdEncoding.EncodeToString(k.Public[:])
}

// EncodePublicBytes base64-encodes arbitrary bytes as a WireGuard key.
func EncodePublicBytes(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// ValidatePublicKey reports whether s is a syntactically valid base64 WireGuard
// public key.
func ValidatePublicKey(s string) error {
	if s == "" {
		return fmt.Errorf("public key is empty")
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return fmt.Errorf("public key is not valid base64")
	}
	if len(raw) != KeySize {
		return fmt.Errorf("public key must be %d bytes", KeySize)
	}
	return nil
}

// EqualPublic compares two base64 public keys in constant time.
func EqualPublic(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
