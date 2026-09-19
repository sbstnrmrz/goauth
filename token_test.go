package goauth

import (
	"strings"
	"testing"
)

func TestGenerateToken_IsRandomAndURLSafe(t *testing.T) {
	first, err := generateToken()
	if err != nil {
		t.Fatalf("generateToken returned error: %v", err)
	}

	second, err := generateToken()
	if err != nil {
		t.Fatalf("generateToken returned error: %v", err)
	}

	if first == second {
		t.Fatal("two tokens are identical")
	}

	// 256 bits in base64url without padding is 43 characters.
	if len(first) != 43 {
		t.Fatalf("expected a 43-character token, got %d: %q", len(first), first)
	}

	if strings.ContainsAny(first, "+/=") {
		t.Fatalf("token is not URL-safe: %q", first)
	}
}

func TestHashToken_IsStableAndNotThePlaintext(t *testing.T) {
	if hashToken("tok") != hashToken("tok") {
		t.Fatal("hashToken is not stable")
	}

	if hashToken("tok") == "tok" {
		t.Fatal("hashToken returned the plaintext")
	}

	if hashToken("tok") == hashToken("other") {
		t.Fatal("two different tokens share a digest")
	}
}

// The stored identifier must carry the prefix DeleteUserResetTokens matches on
// with LIKE 'password-reset:%', and must never contain the raw token.
func TestResetTokenIdentifier_IsPrefixedAndHashed(t *testing.T) {
	identifier := resetTokenIdentifier("tok")

	if !strings.HasPrefix(identifier, "password-reset:") {
		t.Fatalf("identifier lacks the prefix: %q", identifier)
	}

	if strings.Contains(identifier, "tok") {
		t.Fatalf("identifier leaks the raw token: %q", identifier)
	}
}
