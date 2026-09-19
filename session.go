package goauth

import (
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v5"

	"github.com/sbstnrmrz/goauth/authdb"
)

func (a *Auth) createSession(c *echo.Context, userID int64) (authdb.Session, error) {
	token, err := generateToken()
	if err != nil {
		return authdb.Session{}, err
	}

	expiresAt := time.Now().Add(a.cfg.SessionTTL)

	session, err := a.q.CreateSession(c.Request().Context(), authdb.CreateSessionParams{
		Token:     token,
		UserID:    userID,
		ExpiresAt: pgtype.Timestamptz{Time: expiresAt, Valid: true},
		IpAddress: pgtype.Text{String: c.RealIP(), Valid: c.RealIP() != ""},
		UserAgent: pgtype.Text{String: c.Request().UserAgent(), Valid: c.Request().UserAgent() != ""},
	})
	if err != nil {
		return authdb.Session{}, err
	}

	a.setSessionCookie(c, token, expiresAt)

	return session, nil
}

func (a *Auth) setSessionCookie(c *echo.Context, token string, expiresAt time.Time) {
	c.SetCookie(&http.Cookie{
		Name:     a.cfg.CookieName,
		Value:    token,
		Expires:  expiresAt,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.cfg.Secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *Auth) clearSessionCookie(c *echo.Context) {
	c.SetCookie(&http.Cookie{
		Name:     a.cfg.CookieName,
		Value:    "",
		Expires:  time.Unix(0, 0),
		Path:     "/",
		HttpOnly: true,
		Secure:   a.cfg.Secure,
		SameSite: http.SameSiteLaxMode,
	})
}

const contextUserIDKey = "user_id"
const contextUserRoleKey = "user_role"

// SetUserID and SetRole are how RequireAuth publishes the authenticated
// identity onto the request context; handlers read it back with
// UserIDFromContext and RoleFromContext.
func SetUserID(c *echo.Context, userID int64) {
	c.Set(contextUserIDKey, userID)
}

func SetRole(c *echo.Context, role string) {
	c.Set(contextUserRoleKey, role)
}

func UserIDFromContext(c *echo.Context) (int64, bool) {
	userID, ok := c.Get(contextUserIDKey).(int64)
	return userID, ok
}

func RoleFromContext(c *echo.Context) (string, bool) {
	role, ok := c.Get(contextUserRoleKey).(string)
	return role, ok
}
