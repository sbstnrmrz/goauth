package goauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// resetTokenPrefix must stay in sync with the hardcoded 'password-reset:%'
// LIKE pattern in DeleteUserResetTokens (queries/verifications.sql) — that
// query matches identifiers built from this constant, not the constant
// itself, so changing one without the other silently stops the delete from
// matching.
const resetTokenPrefix = "password-reset:"

// generateToken returns a URL-safe, 256-bit random token.
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// hashToken derives the value stored in the database for a token. Tokens carry
// 256 bits of entropy, so a fast digest is enough here - unlike passwords, they
// are not guessable and do not need a slow KDF.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// resetTokenIdentifier is the verifications.identifier for a password reset
// token. Only the hash is ever stored, so a database leak cannot be replayed.
func resetTokenIdentifier(token string) string {
	return resetTokenPrefix + hashToken(token)
}
