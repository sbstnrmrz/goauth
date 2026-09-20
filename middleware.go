package goauth

import (
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/labstack/echo/v5"
)

// RequireRole restricts a route to users holding one of the given roles. It
// runs after RequireAuth, which puts the role on the context.
func RequireRole(roles ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			role, ok := RoleFromContext(c)
			if !ok {
				return c.String(http.StatusForbidden, "forbidden")
			}

			if !slices.Contains(roles, role) {
				return c.String(http.StatusForbidden, "forbidden")
			}

			return next(c)
		}
	}
}

// isPublic reports whether a request runs without a session. Two things exempt
// one, and nothing else does:
//
//	the mounted prefix  signing in is how a session is obtained, so by
//	                    definition there is not one yet. Mount records it.
//	Config.Skipper      the consumer's own public routes. Each must carry its
//	                    own defence; a route that authenticates nothing does
//	                    not belong here.
//
// Echo v5 applies middleware registered with e.Use to every route regardless
// of where the route was registered, so registration order exempts nothing.
// This function is the only exemption.
func (a *Auth) isPublic(c *echo.Context) bool {
	p := c.Request().URL.Path
	if a.prefix != "" && (p == a.prefix || strings.HasPrefix(p, a.prefix+"/")) {
		return true
	}

	if a.cfg.Skipper != nil && a.cfg.Skipper(c) {
		return true
	}

	return false
}

// RequireAuth reads the session cookie, loads the session and publishes the
// caller onto the request context.
func (a *Auth) RequireAuth() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			if a.isPublic(c) {
				return next(c)
			}

			cookie, err := c.Cookie(a.cfg.CookieName)
			if err != nil || cookie.Value == "" {
				return c.String(http.StatusUnauthorized, "authentication required")
			}

			row, err := a.q.GetSessionByToken(c.Request().Context(), cookie.Value)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return c.String(http.StatusUnauthorized, "authentication required")
				}
				slog.Error("failed to load session", "error", err)
				return c.String(http.StatusInternalServerError, "failed to authenticate")
			}

			if row.Session.ExpiresAt.Time.Before(time.Now()) {
				return c.String(http.StatusUnauthorized, "session expired")
			}

			SetUserID(c, row.Session.UserID)
			SetRole(c, row.Role)

			return next(c)
		}
	}
}
