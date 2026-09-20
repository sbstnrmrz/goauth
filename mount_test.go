package goauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v5"
	"github.com/pashagolub/pgxmock/v5"
)

// Mount must register all six routes; a missing one is a 404 the consumer only
// discovers in the browser.
func TestMount_RegistersEveryRoute(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	e := echo.New()
	a := newAuth(t, mock, Config{})
	a.Mount(e, "/auth")

	// Echo v5 exposes the route table through the router, not the Echo value,
	// and RouteInfo carries fields rather than accessor methods.
	routes := map[string]bool{}
	for _, r := range e.Router().Routes() {
		routes[r.Method+" "+r.Path] = true
	}

	for _, want := range []string{
		"POST /auth/signup",
		"POST /auth/login",
		"POST /auth/logout",
		"POST /auth/forgot-password",
		"POST /auth/reset-password",
		"POST /auth/reset-password/verify",
	} {
		if !routes[want] {
			t.Errorf("route not registered: %s", want)
		}
	}
}

func TestMount_RecordsThePrefix(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	a := newAuth(t, mock, Config{})
	a.Mount(echo.New(), "/api/auth")

	if a.prefix != "/api/auth" {
		t.Fatalf("expected the prefix to be recorded, got %q", a.prefix)
	}
}

// End to end through a real router: an unmounted route needs a session, a
// mounted one does not.
func TestMount_MountedRoutesBypassRequireAuth(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	e := echo.New()
	a := newAuth(t, mock, Config{})
	a.Mount(e, "/auth")
	e.Use(a.RequireAuth())
	e.GET("/private", func(c *echo.Context) error { return c.NoContent(http.StatusOK) })

	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/private", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected /private to require a session, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/auth/login", nil))
	if rec.Code == http.StatusUnauthorized {
		t.Fatal("/auth/login must not require a session")
	}
}
