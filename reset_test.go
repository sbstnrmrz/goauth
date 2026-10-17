package goauth

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/pashagolub/pgxmock/v5"
)

// recordingSender captures what would have been emailed.
type recordingSender struct {
	mu                          sync.Mutex
	sent                        bool
	to, subject, text, htmlBody string
}

func (s *recordingSender) Send(ctx context.Context, to, subject, plainText, html string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent, s.to, s.subject, s.text, s.htmlBody = true, to, subject, plainText, html
	return nil
}

func (s *recordingSender) wait(t *testing.T) {
	t.Helper()

	// Delivery is detached, so poll briefly rather than sleeping a fixed time.
	for i := 0; i < 100; i++ {
		s.mu.Lock()
		sent := s.sent
		s.mu.Unlock()
		if sent {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatal("the reset email was never sent")
}

// verificationRow builds the row returned by the verification queries
// (GetVerificationByIdentifier, CreateVerification).
func verificationRow(identifier, value string, expiresAt time.Time) *pgxmock.Rows {
	return pgxmock.NewRows([]string{
		"id", "identifier", "value", "expires_at", "created_at", "updated_at",
	}).AddRow(
		tid(1), identifier, value,
		pgtype.Timestamptz{Time: expiresAt, Valid: true},
		pgtype.Timestamptz{}, pgtype.Timestamptz{},
	)
}

// capturingArg records the string argument the handler passed, so a test can
// compare it against the token that was emailed.
type capturingArg struct{ got *string }

func (a capturingArg) Match(v any) bool {
	s, ok := v.(string)
	if ok {
		*a.got = s
	}
	return ok
}

func TestForgotPassword_SendsResetLink(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	mock.ExpectQuery("SELECT (.+) FROM accounts").
		WithArgs("user@example.com", "credential").
		WillReturnRows(accountRow(tid(7), "irrelevant"))
	mock.ExpectQuery("SELECT (.+) FROM users").
		WithArgs(tid(7)).
		WillReturnRows(userRow(tid(7), "Ada", "user@example.com", "user"))
	mock.ExpectExec("DELETE FROM verifications").
		WithArgs(tid(7).String()).
		WillReturnResult(pgxmock.NewResult("DELETE", 0))
	mock.ExpectQuery("INSERT INTO verifications").
		WithArgs(pgxmock.AnyArg(), tid(7).String(), pgxmock.AnyArg()).
		WillReturnRows(verificationRow("password-reset:hash", tid(7).String(), time.Now().Add(time.Hour)))

	sender := &recordingSender{}
	a := newAuth(t, mock, Config{Mailer: sender})

	_, rec := serve(t, a.ForgotPassword(), http.MethodPost, "/auth/forgot-password",
		`{"email":"user@example.com"}`)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d (body: %s)", http.StatusNoContent, rec.Code, rec.Body.String())
	}

	sender.wait(t)

	if sender.to != "user@example.com" {
		t.Fatalf("expected email to user@example.com, got %s", sender.to)
	}

	if !strings.Contains(sender.text, "token=") {
		t.Fatalf("expected a reset link in the body, got: %s", sender.text)
	}

	if !strings.Contains(sender.htmlBody, "token=") {
		t.Fatalf("expected a reset link in the html body, got: %s", sender.htmlBody)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestForgotPassword_StoresOnlyTokenHash(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	var storedIdentifier string

	mock.ExpectQuery("SELECT (.+) FROM accounts").
		WithArgs("user@example.com", "credential").
		WillReturnRows(accountRow(tid(7), "irrelevant"))
	mock.ExpectQuery("SELECT (.+) FROM users").
		WithArgs(tid(7)).
		WillReturnRows(userRow(tid(7), "Ada", "user@example.com", "user"))
	mock.ExpectExec("DELETE FROM verifications").
		WithArgs(tid(7).String()).
		WillReturnResult(pgxmock.NewResult("DELETE", 0))
	mock.ExpectQuery("INSERT INTO verifications").
		WithArgs(capturingArg{got: &storedIdentifier}, tid(7).String(), pgxmock.AnyArg()).
		WillReturnRows(verificationRow("password-reset:hash", tid(7).String(), time.Now().Add(time.Hour)))

	sender := &recordingSender{}
	a := newAuth(t, mock, Config{Mailer: sender})

	_, rec := serve(t, a.ForgotPassword(), http.MethodPost, "/auth/forgot-password",
		`{"email":"user@example.com"}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d (body: %s)", http.StatusNoContent, rec.Code, rec.Body.String())
	}

	sender.wait(t)

	// Pull the raw token out of the emailed link, then confirm the database
	// received its hash and never the token itself.
	idx := strings.Index(sender.text, "token=")
	if idx == -1 {
		t.Fatalf("no token in email body: %s", sender.text)
	}
	token := strings.Fields(sender.text[idx+len("token="):])[0]

	if token == "" {
		t.Fatal("emailed link carried an empty token")
	}

	if strings.Contains(storedIdentifier, token) {
		t.Fatalf("stored identifier leaks the raw token: %s", storedIdentifier)
	}

	if storedIdentifier != resetTokenIdentifier(token) {
		t.Fatalf("stored identifier %q is not the hash of the emailed token", storedIdentifier)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestForgotPassword_NoMailerConfigured(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	// No expectations are set: the guard must trip before any account lookup,
	// so a misconfigured deployment never writes a reset row it cannot deliver.
	a := newAuth(t, mock, Config{})

	_, rec := serve(t, a.ForgotPassword(), http.MethodPost, "/auth/forgot-password",
		`{"email":"user@example.com"}`)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d (body: %s)", http.StatusInternalServerError, rec.Code, rec.Body.String())
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestForgotPassword_UsesConfiguredResetURL(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	hashed, err := HashPassword("whatever")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}

	mock.ExpectQuery("SELECT (.+) FROM accounts").
		WithArgs("user@example.test", "credential").
		WillReturnRows(accountRow(tid(7), hashed))
	mock.ExpectQuery("SELECT (.+) FROM users").
		WithArgs(tid(7)).
		WillReturnRows(userRow(tid(7), "User", "user@example.test", "user"))
	mock.ExpectExec("DELETE FROM verifications").
		WithArgs(tid(7).String()).
		WillReturnResult(pgxmock.NewResult("DELETE", 0))
	mock.ExpectQuery("INSERT INTO verifications").
		WithArgs(pgxmock.AnyArg(), tid(7).String(), pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "identifier", "value", "expires_at", "created_at", "updated_at",
		}).AddRow(
			tid(1), "password-reset:abc", tid(7).String(),
			pgtype.Timestamptz{Time: time.Now().Add(time.Minute), Valid: true},
			pgtype.Timestamptz{}, pgtype.Timestamptz{},
		))

	sender := &recordingSender{}
	a := newAuth(t, mock, Config{
		Mailer:   sender,
		ResetURL: func(token string) string { return "https://app.example.test/nueva-clave?t=" + token },
	})

	_, rec := serve(t, a.ForgotPassword(), http.MethodPost, "/auth/forgot-password",
		`{"email":"user@example.test"}`)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}

	sender.wait(t)

	if sender.to != "user@example.test" {
		t.Fatalf("emailed the wrong address: %q", sender.to)
	}

	if !strings.Contains(sender.text, "https://app.example.test/nueva-clave?t=") {
		t.Fatalf("the email does not carry the configured link: %q", sender.text)
	}
}

func TestForgotPassword_UsesConfiguredEmailCopy(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	hashed, err := HashPassword("whatever")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}

	mock.ExpectQuery("SELECT (.+) FROM accounts").
		WithArgs("user@example.test", "credential").
		WillReturnRows(accountRow(tid(7), hashed))
	mock.ExpectQuery("SELECT (.+) FROM users").
		WithArgs(tid(7)).
		WillReturnRows(userRow(tid(7), "User", "user@example.test", "user"))
	mock.ExpectExec("DELETE FROM verifications").
		WithArgs(tid(7).String()).
		WillReturnResult(pgxmock.NewResult("DELETE", 0))
	mock.ExpectQuery("INSERT INTO verifications").
		WithArgs(pgxmock.AnyArg(), tid(7).String(), pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "identifier", "value", "expires_at", "created_at", "updated_at",
		}).AddRow(
			tid(1), "password-reset:abc", tid(7).String(),
			pgtype.Timestamptz{Time: time.Now().Add(time.Minute), Valid: true},
			pgtype.Timestamptz{}, pgtype.Timestamptz{},
		))

	sender := &recordingSender{}
	a := newAuth(t, mock, Config{
		Mailer: sender,
		ResetEmail: func(name, link string, expiry time.Duration) (string, string, string) {
			return "Recuperá tu contraseña", "Hola " + name + ": " + link, "<p>" + link + "</p>"
		},
	})

	_, rec := serve(t, a.ForgotPassword(), http.MethodPost, "/auth/forgot-password",
		`{"email":"user@example.test"}`)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}

	sender.wait(t)

	if sender.subject != "Recuperá tu contraseña" {
		t.Fatalf("expected the configured subject, got %q", sender.subject)
	}
}

// An unknown address must answer exactly like a known one, or the endpoint
// tells an attacker which emails are registered.
func TestForgotPassword_UnknownEmailAnswers204(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	mock.ExpectQuery("SELECT (.+) FROM accounts").
		WithArgs("nobody@example.test", "credential").
		WillReturnError(pgx.ErrNoRows)

	sender := &recordingSender{}
	a := newAuth(t, mock, Config{Mailer: sender})

	_, rec := serve(t, a.ForgotPassword(), http.MethodPost, "/auth/forgot-password",
		`{"email":"nobody@example.test"}`)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}

	if sender.sent {
		t.Fatal("an email was sent for an unknown address")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestVerifyResetToken_ValidTokenIsNotConsumed(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	identifier := resetTokenIdentifier("live-token")

	// Only a SELECT is expected. pgxmock fails the test if the handler issues
	// a DELETE, which is what keeps verification non-destructive.
	mock.ExpectQuery("SELECT (.+) FROM verifications").
		WithArgs(identifier).
		WillReturnRows(verificationRow(identifier, tid(7).String(), time.Now().Add(time.Hour)))

	a := newAuth(t, mock, Config{})

	_, rec := serve(t, a.VerifyResetToken(), http.MethodPost, "/auth/reset-password/verify",
		`{"token":"live-token"}`)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d (body: %s)", http.StatusNoContent, rec.Code, rec.Body.String())
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestVerifyResetToken_UnknownToken(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	mock.ExpectQuery("SELECT (.+) FROM verifications").
		WithArgs(resetTokenIdentifier("nope")).
		WillReturnError(pgx.ErrNoRows)

	a := newAuth(t, mock, Config{})

	_, rec := serve(t, a.VerifyResetToken(), http.MethodPost, "/auth/reset-password/verify",
		`{"token":"nope"}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d (body: %s)", http.StatusBadRequest, rec.Code, rec.Body.String())
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestVerifyResetToken_ExpiredTokenIsCleanedUp(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	identifier := resetTokenIdentifier("stale")

	mock.ExpectQuery("SELECT (.+) FROM verifications").
		WithArgs(identifier).
		WillReturnRows(verificationRow(identifier, tid(7).String(), time.Now().Add(-time.Minute)))
	mock.ExpectExec("DELETE FROM verifications").
		WithArgs(identifier).
		WillReturnResult(pgxmock.NewResult("DELETE", 1))

	a := newAuth(t, mock, Config{})

	_, rec := serve(t, a.VerifyResetToken(), http.MethodPost, "/auth/reset-password/verify",
		`{"token":"stale"}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d (body: %s)", http.StatusBadRequest, rec.Code, rec.Body.String())
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestVerifyResetToken_MissingToken(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	a := newAuth(t, mock, Config{})

	_, rec := serve(t, a.VerifyResetToken(), http.MethodPost, "/auth/reset-password/verify",
		`{"token":""}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d (body: %s)", http.StatusBadRequest, rec.Code, rec.Body.String())
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestResetPassword_InvalidToken(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	mock.ExpectQuery("SELECT (.+) FROM verifications").
		WithArgs(resetTokenIdentifier("bogus")).
		WillReturnError(pgx.ErrNoRows)

	a := newAuth(t, mock, Config{})

	_, rec := serve(t, a.ResetPassword(), http.MethodPost, "/auth/reset-password",
		`{"token":"bogus","newPassword":"new12345"}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d (body: %s)", http.StatusBadRequest, rec.Code, rec.Body.String())
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestResetPassword_ExpiredToken(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	identifier := resetTokenIdentifier("stale")

	mock.ExpectQuery("SELECT (.+) FROM verifications").
		WithArgs(identifier).
		WillReturnRows(verificationRow(identifier, tid(7).String(), time.Now().Add(-time.Minute)))
	mock.ExpectExec("DELETE FROM verifications").
		WithArgs(identifier).
		WillReturnResult(pgxmock.NewResult("DELETE", 1))

	a := newAuth(t, mock, Config{})

	_, rec := serve(t, a.ResetPassword(), http.MethodPost, "/auth/reset-password",
		`{"token":"stale","newPassword":"new12345"}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d (body: %s)", http.StatusBadRequest, rec.Code, rec.Body.String())
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestResetPassword_ShortPassword(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	a := newAuth(t, mock, Config{})

	_, rec := serve(t, a.ResetPassword(), http.MethodPost, "/auth/reset-password",
		`{"token":"whatever","newPassword":"short"}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d (body: %s)", http.StatusBadRequest, rec.Code, rec.Body.String())
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestResetPassword_MissingFields(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"missing token", `{"newPassword":"new12345"}`},
		{"missing password", `{"token":"abc"}`},
		{"both empty", `{"token":"","newPassword":""}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mock, err := pgxmock.NewPool()
			if err != nil {
				t.Fatalf("failed to create mock pool: %v", err)
			}
			defer mock.Close()

			a := newAuth(t, mock, Config{})

			_, rec := serve(t, a.ResetPassword(), http.MethodPost, "/auth/reset-password", tc.body)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected status %d, got %d (body: %s)", http.StatusBadRequest, rec.Code, rec.Body.String())
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("unmet expectations: %v", err)
			}
		})
	}
}

func TestResetPassword_AlreadyConsumedToken(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	identifier := resetTokenIdentifier("raced")

	mock.ExpectQuery("SELECT (.+) FROM verifications").
		WithArgs(identifier).
		WillReturnRows(verificationRow(identifier, tid(7).String(), time.Now().Add(time.Hour)))
	// A concurrent redemption won the race, so the claim deletes nothing.
	mock.ExpectExec("DELETE FROM verifications").
		WithArgs(identifier).
		WillReturnResult(pgxmock.NewResult("DELETE", 0))

	a := newAuth(t, mock, Config{})

	_, rec := serve(t, a.ResetPassword(), http.MethodPost, "/auth/reset-password",
		`{"token":"raced","newPassword":"new12345"}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d (body: %s)", http.StatusBadRequest, rec.Code, rec.Body.String())
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestResetPassword_UpdatesPasswordAndClearsSessions(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	identifier := resetTokenIdentifier("good-token")

	mock.ExpectQuery("SELECT (.+) FROM verifications").
		WithArgs(identifier).
		WillReturnRows(verificationRow(identifier, tid(7).String(), time.Now().Add(time.Hour)))
	mock.ExpectExec("DELETE FROM verifications").
		WithArgs(identifier).
		WillReturnResult(pgxmock.NewResult("DELETE", 1))
	mock.ExpectExec("UPDATE accounts").
		WithArgs(pgxmock.AnyArg(), tid(7), "credential").
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	mock.ExpectExec("DELETE FROM sessions").
		WithArgs(tid(7)).
		WillReturnResult(pgxmock.NewResult("DELETE", 2))

	a := newAuth(t, mock, Config{})

	_, rec := serve(t, a.ResetPassword(), http.MethodPost, "/auth/reset-password",
		`{"token":"good-token","newPassword":"new12345"}`)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d (body: %s)", http.StatusNoContent, rec.Code, rec.Body.String())
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
