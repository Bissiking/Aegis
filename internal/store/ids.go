package store

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"strings"
)

var idAlphabet = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// NewID returns a URL-safe, non-enumerable opaque identifier with a short
// human-readable prefix (e.g. "dev_9k2m...").
func NewID(prefix string) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is fatal for identifiers; panic is intentional.
		panic(fmt.Sprintf("crypto/rand unavailable: %v", err))
	}
	return prefix + "_" + strings.ToLower(idAlphabet.EncodeToString(b))
}

// RandomToken returns a cryptographically random opaque token (base64url).
func RandomToken(nbytes int) (string, error) {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
