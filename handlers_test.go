package goauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v5"
	"github.com/pashagolub/pgxmock/v5"
)

// accountRow builds the row returned by the account queries (GetAccountByEmail,
// GetAccountByUserID).
func accountRow(userID uuid.UUID, hashedPassword string) *pgxmock.Rows {
	return pgxmock.NewRows([]string{
		"id", "user_id", "provider_id", "account_id", "password",
		"access_token", "refresh_token", "access_token_expires_at",
		"refresh_token_expires_at", "scope", "created_at", "updated_at",
	}).AddRow(
		tid(1), userID, "credential", "user@example.test",
		pgtype.Text{String: hashedPassword, Valid: true},
		pgtype.Text{}, pgtype.Text{},
		pgtype.Timestamptz{}, pgtype.Timestamptz{},
		pgtype.Text{}, pgtype.Timestamptz{}, pgtype.Timestamptz{},
	)
}

func userRow(id uuid.UUID, name, email, role string) *pgxmock.Rows {
	return pgxmock.NewRows([]string{
		"id", "name", "email", "image", "role", "created_at", "updated_at",
	}).AddRow(
		id, name, email, pgtype.Text{}, role,
		pgtype.Timestamptz{}, pgtype.Timestamptz{},
	)
}

// serve runs one request against a handler and returns the recorder.
func serve(t *testing.T, handler echo.HandlerFunc, method, path, body string) (*echo.Context, *httptest.ResponseRecorder) {
	t.Helper()

	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(req, rec)

	if err := handler(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	return c, rec
}

// changePasswordContext builds the request/context pair ChangePassword expects,
// optionally publishing an authenticated user id the way RequireAuth would.
func changePasswordContext(t *testing.T, body string, userID uuid.UUID, authenticated bool) (*echo.Context, *httptest.ResponseRecorder) {
	t.Helper()

	req := httptest.NewRequest(http.MethodPatch, "/users/me/password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(req, rec)
	if authenticated {
		SetUserID(c, userID)
	}

	return c, rec
}

func TestChangePassword_Unauthenticated(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	a := newAuth(t, mock, Config{})
	c, rec := changePasswordContext(t, `{"currentPassword":"old12345","newPassword":"new12345"}`, uuid.Nil, false)

	if err := a.ChangePassword()(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d (body: %s)", http.StatusUnauthorized, rec.Code, rec.Body.String())
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestChangePassword_MissingFields(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"missing current password", `{"newPassword":"new12345"}`},
		{"missing new password", `{"currentPassword":"old12345"}`},
		{"both empty", `{"currentPassword":"","newPassword":""}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mock, err := pgxmock.NewPool()
			if err != nil {
				t.Fatalf("failed to create mock pool: %v", err)
			}
			defer mock.Close()

			a := newAuth(t, mock, Config{})
			c, rec := changePasswordContext(t, tc.body, tid(1), true)

			if err := a.ChangePassword()(c); err != nil {
				t.Fatalf("handler returned error: %v", err)
			}

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected status %d, got %d (body: %s)", http.StatusBadRequest, rec.Code, rec.Body.String())
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("unmet expectations: %v", err)
			}
		})
	}
}

func TestChangePassword_NewPasswordTooShort(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	a := newAuth(t, mock, Config{})
	c, rec := changePasswordContext(t, `{"currentPassword":"old12345","newPassword":"short"}`, tid(1), true)

	if err := a.ChangePassword()(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d (body: %s)", http.StatusBadRequest, rec.Code, rec.Body.String())
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestChangePassword_InvalidJSON(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	a := newAuth(t, mock, Config{})
	c, rec := changePasswordContext(t, `not json`, tid(1), true)

	if err := a.ChangePassword()(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d (body: %s)", http.StatusBadRequest, rec.Code, rec.Body.String())
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestChangePassword_NoCredentialAccount(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	mock.ExpectQuery("SELECT (.+) FROM accounts").
		WithArgs(tid(1), "credential").
		WillReturnError(pgx.ErrNoRows)

	a := newAuth(t, mock, Config{})
	c, rec := changePasswordContext(t, `{"currentPassword":"old12345","newPassword":"new12345"}`, tid(1), true)

	if err := a.ChangePassword()(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d (body: %s)", http.StatusBadRequest, rec.Code, rec.Body.String())
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestChangePassword_FetchAccountDatabaseError(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	mock.ExpectQuery("SELECT (.+) FROM accounts").
		WithArgs(tid(1), "credential").
		WillReturnError(pgx.ErrTxClosed)

	a := newAuth(t, mock, Config{})
	c, rec := changePasswordContext(t, `{"currentPassword":"old12345","newPassword":"new12345"}`, tid(1), true)

	if err := a.ChangePassword()(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d (body: %s)", http.StatusInternalServerError, rec.Code, rec.Body.String())
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestChangePassword_WrongCurrentPassword(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	hashed, err := HashPassword("correct-password")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	mock.ExpectQuery("SELECT (.+) FROM accounts").
		WithArgs(tid(1), "credential").
		WillReturnRows(accountRow(tid(1), hashed))

	a := newAuth(t, mock, Config{})
	c, rec := changePasswordContext(t, `{"currentPassword":"wrong-password","newPassword":"new12345"}`, tid(1), true)

	if err := a.ChangePassword()(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d (body: %s)", http.StatusUnauthorized, rec.Code, rec.Body.String())
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestChangePassword_Success(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	hashed, err := HashPassword("correct-password")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	mock.ExpectQuery("SELECT (.+) FROM accounts").
		WithArgs(tid(1), "credential").
		WillReturnRows(accountRow(tid(1), hashed))

	mock.ExpectExec("UPDATE accounts").
		WithArgs(pgxmock.AnyArg(), tid(1), "credential").
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	a := newAuth(t, mock, Config{})
	c, rec := changePasswordContext(t, `{"currentPassword":"correct-password","newPassword":"brand-new-password"}`, tid(1), true)

	if err := a.ChangePassword()(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d (body: %s)", http.StatusNoContent, rec.Code, rec.Body.String())
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestChangePassword_UpdateDatabaseError(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	hashed, err := HashPassword("correct-password")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	mock.ExpectQuery("SELECT (.+) FROM accounts").
		WithArgs(tid(1), "credential").
		WillReturnRows(accountRow(tid(1), hashed))

	mock.ExpectExec("UPDATE accounts").
		WithArgs(pgxmock.AnyArg(), tid(1), "credential").
		WillReturnError(pgx.ErrTxClosed)

	a := newAuth(t, mock, Config{})
	c, rec := changePasswordContext(t, `{"currentPassword":"correct-password","newPassword":"brand-new-password"}`, tid(1), true)

	if err := a.ChangePassword()(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d (body: %s)", http.StatusInternalServerError, rec.Code, rec.Body.String())
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestLogin_WrongPasswordIsUnauthorized(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	hashed, err := HashPassword("right")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}

	mock.ExpectQuery("SELECT (.+) FROM accounts").
		WithArgs("user@example.test", "credential").
		WillReturnRows(accountRow(tid(7), hashed))

	a := newAuth(t, mock, Config{})
	_, rec := serve(t, a.Login(), http.MethodPost, "/auth/login",
		`{"email":"user@example.test","password":"wrong"}`)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}

	// The message must not distinguish a bad password from an unknown email.
	if body := rec.Body.String(); body != "invalid email or password" {
		t.Fatalf("unexpected body: %q", body)
	}
}

func TestLogin_UnknownEmailIsUnauthorized(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	mock.ExpectQuery("SELECT (.+) FROM accounts").
		WithArgs("nobody@example.test", "credential").
		WillReturnError(pgx.ErrNoRows)

	a := newAuth(t, mock, Config{})
	_, rec := serve(t, a.Login(), http.MethodPost, "/auth/login",
		`{"email":"nobody@example.test","password":"whatever"}`)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}

	if body := rec.Body.String(); body != "invalid email or password" {
		t.Fatalf("unexpected body: %q", body)
	}
}

func TestLogin_SuccessSetsCookie(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	hashed, err := HashPassword("right")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}

	mock.ExpectQuery("SELECT (.+) FROM accounts").
		WithArgs("user@example.test", "credential").
		WillReturnRows(accountRow(tid(7), hashed))
	mock.ExpectQuery("SELECT (.+) FROM users").
		WithArgs(tid(7)).
		WillReturnRows(userRow(tid(7), "User", "user@example.test", "user"))
	mock.ExpectQuery("INSERT INTO sessions").
		WithArgs(pgxmock.AnyArg(), tid(7), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "token", "user_id", "expires_at", "ip_address",
			"user_agent", "created_at", "updated_at",
		}).AddRow(
			tid(1), "stored", tid(7),
			pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true},
			pgtype.Text{}, pgtype.Text{},
			pgtype.Timestamptz{}, pgtype.Timestamptz{},
		))

	a := newAuth(t, mock, Config{})
	_, rec := serve(t, a.Login(), http.MethodPost, "/auth/login",
		`{"email":"user@example.test","password":"right"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}

	if len(rec.Result().Cookies()) != 1 {
		t.Fatal("expected a session cookie")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestSignup_DuplicateEmailIsConflict(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO users").
		WithArgs("User", "taken@example.test", pgxmock.AnyArg()).
		WillReturnError(&pgconn.PgError{Code: "23505"})
	mock.ExpectRollback()

	a := newAuth(t, mock, Config{})
	_, rec := serve(t, a.Signup(), http.MethodPost, "/auth/signup",
		`{"name":"User","email":"taken@example.test","password":"password1"}`)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", rec.Code)
	}
}

// OnSignup is the extension point that lets a consumer create its own rows in
// the same transaction; an error from it must roll the user back too.
func TestSignup_OnSignupErrorRollsBack(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO users").
		WithArgs("User", "user@example.test", pgxmock.AnyArg()).
		WillReturnRows(userRow(tid(7), "User", "user@example.test", "user"))
	mock.ExpectQuery("INSERT INTO accounts").
		WithArgs(tid(7), "credential", "user@example.test", pgxmock.AnyArg()).
		WillReturnRows(accountRow(tid(7), "hashed"))
	mock.ExpectRollback()

	a := newAuth(t, mock, Config{
		OnSignup: func(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error {
			return errors.New("consumer said no")
		},
	})

	_, rec := serve(t, a.Signup(), http.MethodPost, "/auth/signup",
		`{"name":"User","email":"user@example.test","password":"password1"}`)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestSignup_ShortPasswordIsBadRequest(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	a := newAuth(t, mock, Config{})
	_, rec := serve(t, a.Signup(), http.MethodPost, "/auth/signup",
		`{"name":"User","email":"user@example.test","password":"short"}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}

	// Validation runs before the transaction opens, so nothing was begun.
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestLogout_DeletesSessionAndClearsCookie(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	mock.ExpectExec("DELETE FROM sessions").
		WithArgs("tok").
		WillReturnResult(pgxmock.NewResult("DELETE", 1))

	a := newAuth(t, mock, Config{})

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: "session_token", Value: "tok"})
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(req, rec)

	if err := a.Logout()(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}

	if got := rec.Result().Cookies()[0].Value; got != "" {
		t.Fatalf("expected the cookie to be cleared, got %q", got)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// Logging out without a cookie is not an error: the caller wanted to end up
// signed out, and they are.
func TestLogout_WithoutCookieSucceeds(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	a := newAuth(t, mock, Config{})
	_, rec := serve(t, a.Logout(), http.MethodPost, "/auth/logout", "")

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
