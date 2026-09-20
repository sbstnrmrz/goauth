package goauth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/labstack/echo/v5"
	"github.com/pashagolub/pgxmock/v5"
)

func TestRequireAuth_PublishesUserAndRole(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	mock.ExpectQuery("SELECT sessions.id").
		WithArgs("tok").
		WillReturnRows(sessionRow(7, "tok", "admin", time.Now().Add(time.Hour)))

	a := newAuth(t, mock, Config{})
	c, _ := requestContext(t, "session_token", "tok")

	var gotUserID int64
	var gotRole string
	handler := a.RequireAuth()(func(c *echo.Context) error {
		gotUserID, _ = UserIDFromContext(c)
		gotRole, _ = RoleFromContext(c)
		return c.NoContent(http.StatusOK)
	})

	if err := handler(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if gotUserID != 7 || gotRole != "admin" {
		t.Fatalf("expected user 7 with role admin, got %d / %q", gotUserID, gotRole)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestRequireAuth_RejectsMissingCookie(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	a := newAuth(t, mock, Config{})
	c, rec := requestContext(t, "session_token", "")

	handler := a.RequireAuth()(func(c *echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	if err := handler(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestRequireAuth_RejectsExpiredSession(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	mock.ExpectQuery("SELECT sessions.id").
		WithArgs("tok").
		WillReturnRows(sessionRow(7, "tok", "user", time.Now().Add(-time.Hour)))

	a := newAuth(t, mock, Config{})
	c, rec := requestContext(t, "session_token", "tok")

	handler := a.RequireAuth()(func(c *echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	if err := handler(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for an expired session, got %d", rec.Code)
	}
}

func TestRequireAuth_RejectsUnknownToken(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	// RequireAuth distinguishes pgx.ErrNoRows (401) from any other database
	// error (500), so the mock must return that exact sentinel — a plain
	// errors.New would take the 500 branch and the test would pass for the
	// wrong reason.
	mock.ExpectQuery("SELECT sessions.id").
		WithArgs("tok").
		WillReturnError(pgx.ErrNoRows)

	a := newAuth(t, mock, Config{})
	c, rec := requestContext(t, "session_token", "tok")

	handler := a.RequireAuth()(func(c *echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	if err := handler(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for an unknown token, got %d", rec.Code)
	}
}

func TestRequireAuth_DatabaseErrorIs500(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	mock.ExpectQuery("SELECT sessions.id").
		WithArgs("tok").
		WillReturnError(errors.New("connection refused"))

	a := newAuth(t, mock, Config{})
	c, rec := requestContext(t, "session_token", "tok")

	handler := a.RequireAuth()(func(c *echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	if err := handler(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for a database failure, got %d", rec.Code)
	}
}

// The mounted prefix is exempt because signing in is how a session is
// obtained: requiring one there would lock everybody out.
func TestRequireAuth_SkipsMountedPrefix(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	a := newAuth(t, mock, Config{})
	a.Mount(echo.New(), "/auth")

	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(req, rec)

	called := false
	handler := a.RequireAuth()(func(c *echo.Context) error {
		called = true
		return c.NoContent(http.StatusOK)
	})

	if err := handler(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if !called {
		t.Fatal("expected the mounted prefix to skip authentication")
	}
}

// The mounted prefix exempts itself and everything under it, and nothing that
// merely starts with the same characters. A naive strings.HasPrefix check
// would also exempt /authors and /authorize, which is the defect this guards
// against.
func TestRequireAuth_PrefixBoundary(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		wantAuth bool // true: reaches the handler unauthenticated; false: 401s
	}{
		{"prefix itself is exempt", "/auth", true},
		{"a route under the prefix is exempt", "/auth/login", true},
		{"a sibling that merely starts with the prefix is not exempt", "/authors", false},
		{"another sibling that merely starts with the prefix is not exempt", "/authorize", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock, err := pgxmock.NewPool()
			if err != nil {
				t.Fatalf("failed to create mock pool: %v", err)
			}
			defer mock.Close()

			a := newAuth(t, mock, Config{})
			a.Mount(echo.New(), "/auth")

			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()
			c := echo.New().NewContext(req, rec)

			called := false
			handler := a.RequireAuth()(func(c *echo.Context) error {
				called = true
				return c.NoContent(http.StatusOK)
			})

			if err := handler(c); err != nil {
				t.Fatalf("handler returned error: %v", err)
			}

			if called != tt.wantAuth {
				t.Fatalf("path %q: expected called=%v, got %v", tt.path, tt.wantAuth, called)
			}

			if !tt.wantAuth && rec.Code != http.StatusUnauthorized {
				t.Fatalf("path %q: expected 401, got %d", tt.path, rec.Code)
			}
		})
	}
}

// The worst-case blast radius: a short prefix like "/user" must not swallow
// an unrelated tree like "/users/me" just because the strings share a prefix.
func TestRequireAuth_PrefixBoundary_WorstCase(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	a := newAuth(t, mock, Config{})
	a.Mount(echo.New(), "/user")

	req := httptest.NewRequest(http.MethodGet, "/users/me", nil)
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(req, rec)

	called := false
	handler := a.RequireAuth()(func(c *echo.Context) error {
		called = true
		return c.NoContent(http.StatusOK)
	})

	if err := handler(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if called {
		t.Fatal("expected /users/me to require authentication despite sharing a prefix with /user")
	}

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

// Skipper is what replaced the hardcoded publicPrefixes list: a consumer's
// webhook route carries its own authentication and sends no cookie.
func TestRequireAuth_HonoursSkipper(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	a := newAuth(t, mock, Config{
		Skipper: func(c *echo.Context) bool {
			return c.Request().URL.Path == "/telegram/webhook/abc"
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook/abc", nil)
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(req, rec)

	called := false
	handler := a.RequireAuth()(func(c *echo.Context) error {
		called = true
		return c.NoContent(http.StatusOK)
	})

	if err := handler(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if !called {
		t.Fatal("expected Skipper to exempt the route")
	}
}

func TestRequireRole_AllowsMatchingRole(t *testing.T) {
	c, _ := requestContext(t, "session_token", "")
	SetRole(c, "admin")

	called := false
	handler := RequireRole("admin")(func(c *echo.Context) error {
		called = true
		return c.NoContent(http.StatusOK)
	})

	if err := handler(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if !called {
		t.Fatal("expected the handler to run for a matching role")
	}
}

func TestRequireRole_RejectsOtherRole(t *testing.T) {
	c, rec := requestContext(t, "session_token", "")
	SetRole(c, "user")

	handler := RequireRole("admin")(func(c *echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	if err := handler(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestRequireRole_RejectsMissingRole(t *testing.T) {
	c, rec := requestContext(t, "session_token", "")

	handler := RequireRole("admin")(func(c *echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	if err := handler(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when no role is on the context, got %d", rec.Code)
	}
}
