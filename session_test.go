package goauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v5"
	"github.com/pashagolub/pgxmock/v5"
)

// newAuth builds an Auth over a mock pool with the given config, filling the
// ResetURL every test needs but few care about.
func newAuth(t *testing.T, mock pgxmock.PgxPoolIface, cfg Config) *Auth {
	t.Helper()

	if cfg.ResetURL == nil {
		cfg.ResetURL = func(token string) string { return "https://example.test/reset?token=" + token }
	}

	a, err := New(mock, cfg)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	return a
}

// sessionRow builds the row returned by GetSessionByToken, which joins the
// session with its user's role.
func sessionRow(userID int64, token, role string, expiresAt time.Time) *pgxmock.Rows {
	return pgxmock.NewRows([]string{
		"id", "token", "user_id", "expires_at", "ip_address",
		"user_agent", "created_at", "updated_at", "role",
	}).AddRow(
		int64(1), token, userID,
		pgtype.Timestamptz{Time: expiresAt, Valid: true},
		pgtype.Text{}, pgtype.Text{},
		pgtype.Timestamptz{}, pgtype.Timestamptz{}, role,
	)
}

func requestContext(t *testing.T, cookieName, token string) (*echo.Context, *httptest.ResponseRecorder) {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/users/me", nil)
	if token != "" {
		req.AddCookie(&http.Cookie{Name: cookieName, Value: token})
	}
	rec := httptest.NewRecorder()

	return echo.New().NewContext(req, rec), rec
}

func TestSetSessionCookie_UsesConfiguredNameAndSecure(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	a := newAuth(t, mock, Config{CookieName: "sid", Secure: true})
	c, rec := requestContext(t, "sid", "")

	a.setSessionCookie(c, "tok", time.Now().Add(time.Hour))

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one cookie, got %d", len(cookies))
	}

	got := cookies[0]
	if got.Name != "sid" {
		t.Fatalf("expected the configured cookie name, got %q", got.Name)
	}

	if !got.Secure {
		t.Fatal("expected Secure to follow the configuration")
	}

	if !got.HttpOnly {
		t.Fatal("the session cookie must be HttpOnly")
	}

	if got.SameSite != http.SameSiteLaxMode {
		t.Fatalf("expected SameSite=Lax, got %v", got.SameSite)
	}
}

// Secure defaults to false so a plain-HTTP development server still receives
// the cookie. The original read APP_ENV in a package var, which no test could
// vary; this asserts the field actually drives the flag.
func TestSetSessionCookie_InsecureWhenNotConfigured(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	a := newAuth(t, mock, Config{})
	c, rec := requestContext(t, "session_token", "")

	a.setSessionCookie(c, "tok", time.Now().Add(time.Hour))

	if rec.Result().Cookies()[0].Secure {
		t.Fatal("expected Secure to be false when not configured")
	}
}

func TestClearSessionCookie_ExpiresIt(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	a := newAuth(t, mock, Config{})
	c, rec := requestContext(t, "session_token", "")

	a.clearSessionCookie(c)

	got := rec.Result().Cookies()[0]
	if got.Value != "" {
		t.Fatalf("expected an empty value, got %q", got.Value)
	}

	if !got.Expires.Before(time.Now()) {
		t.Fatalf("expected an expiry in the past, got %v", got.Expires)
	}
}

func TestCreateSession_StoresTokenAndSetsCookie(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	mock.ExpectQuery("INSERT INTO sessions").
		WithArgs(pgxmock.AnyArg(), int64(7), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "token", "user_id", "expires_at", "ip_address",
			"user_agent", "created_at", "updated_at",
		}).AddRow(
			int64(1), "stored", int64(7),
			pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true},
			pgtype.Text{}, pgtype.Text{},
			pgtype.Timestamptz{}, pgtype.Timestamptz{},
		))

	a := newAuth(t, mock, Config{})
	c, rec := requestContext(t, "session_token", "")

	if _, err := a.createSession(c, 7); err != nil {
		t.Fatalf("createSession returned error: %v", err)
	}

	if len(rec.Result().Cookies()) != 1 {
		t.Fatal("expected createSession to set the session cookie")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestContextAccessors_RoundTrip(t *testing.T) {
	c, _ := requestContext(t, "session_token", "")

	if _, ok := UserIDFromContext(c); ok {
		t.Fatal("expected no user id on a fresh context")
	}

	SetUserID(c, 7)
	SetRole(c, "admin")

	userID, ok := UserIDFromContext(c)
	if !ok || userID != 7 {
		t.Fatalf("expected user id 7, got %d (ok=%v)", userID, ok)
	}

	role, ok := RoleFromContext(c)
	if !ok || role != "admin" {
		t.Fatalf("expected role admin, got %q (ok=%v)", role, ok)
	}
}
