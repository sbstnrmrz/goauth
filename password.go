package goauth

import "golang.org/x/crypto/bcrypt"

// HashPassword returns a bcrypt digest of plain, salted by bcrypt itself.
func HashPassword(plain string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// CheckPassword reports whether plain is the password behind hash. A non-nil
// error means it is not; callers must not distinguish the reasons in what they
// tell the caller.
func CheckPassword(plain, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain))
}
