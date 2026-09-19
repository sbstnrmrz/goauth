package goauth

import "testing"

func TestHashPassword_RoundTrips(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}

	if hash == "correct horse battery staple" {
		t.Fatal("hash is the plaintext")
	}

	if err := CheckPassword("correct horse battery staple", hash); err != nil {
		t.Fatalf("CheckPassword rejected the right password: %v", err)
	}
}

func TestCheckPassword_RejectsWrongPassword(t *testing.T) {
	hash, err := HashPassword("right")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}

	if err := CheckPassword("wrong", hash); err == nil {
		t.Fatal("CheckPassword accepted the wrong password")
	}
}

// bcrypt salts, so the same password hashes differently every time. A test
// asserting a fixed digest would pass only by accident.
func TestHashPassword_IsSalted(t *testing.T) {
	first, err := HashPassword("same")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}

	second, err := HashPassword("same")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}

	if first == second {
		t.Fatal("two hashes of the same password are identical, so it is unsalted")
	}
}
