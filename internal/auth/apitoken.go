package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"strings"
	"time"
)

// tokenPrefix self-identifies an MCP API token (secret-scanner friendly; cheap reject).
const tokenPrefix = "patdmcp_"

// b32 is lowercase, unpadded base32: charset [a-z2-7], so a token never contains '_'
// and splits cleanly on '_'. The id/secret are opaque strings (the secret is hashed
// as-is, the id is a lookup key) — never base32-decoded — so lowercasing is free.
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func randBase32(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return strings.ToLower(b32.EncodeToString(b)), nil
}

// newToken returns (id, secret, fullToken). id is 10 random bytes, secret is 32
// (~256-bit). fullToken is the only place the secret appears in clear.
func newToken() (id, secret, full string, err error) {
	if id, err = randBase32(10); err != nil {
		return "", "", "", err
	}
	if secret, err = randBase32(32); err != nil {
		return "", "", "", err
	}
	return id, secret, tokenPrefix + id + "_" + secret, nil
}

// parseToken splits "patdmcp_<id>_<secret>" into its parts.
func parseToken(s string) (id, secret string, ok bool) {
	rest, found := strings.CutPrefix(s, tokenPrefix)
	if !found {
		return "", "", false
	}
	id, secret, found = strings.Cut(rest, "_")
	if !found || id == "" || secret == "" {
		return "", "", false
	}
	return id, secret, true
}

// hashSecret is sha256(secret) as hex. SHA-256 (not argon2) is correct here: the
// secret is 256-bit random, so a fast hash is safe and avoids per-request argon2 cost.
func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// verifySecret reports whether secret hashes to storedHash, using a constant-time
// comparison to avoid a timing oracle on the hash bytes. This is the single point
// where a presented secret is checked against a stored hash.
func verifySecret(secret, storedHash string) bool {
	return subtle.ConstantTimeCompare([]byte(hashSecret(secret)), []byte(storedHash)) == 1
}

// APIToken is one stored credential. The secret itself is never stored.
type APIToken struct {
	ID         string     `json:"id"`
	SecretHash string     `json:"secret_hash"`
	Role       Role       `json:"role"`
	Label      string     `json:"label"`
	Created    time.Time  `json:"created"`
	Expires    *time.Time `json:"expires,omitempty"`
	Disabled   bool       `json:"disabled,omitempty"`
	LastUsed   *time.Time `json:"last_used,omitempty"`
}
