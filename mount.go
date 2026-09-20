package goauth

import (
	"strings"

	"github.com/labstack/echo/v5"
)

// Mount creates a group at prefix, registers the authentication routes on it
// and records the prefix, which is what RequireAuth exempts. It takes the
// prefix rather than a ready-made *echo.Group because Echo v5 does not expose
// a group's prefix: there is no (*echo.Group).Prefix(), and the field is
// unexported.
//
// A trailing slash on prefix is stripped before it is recorded, so "/auth/"
// and "/auth" behave identically.
//
// A consumer that wires the handlers individually instead has no recorded
// prefix and must exempt its login routes through Config.Skipper.
func (a *Auth) Mount(e *echo.Echo, prefix string) {
	prefix = strings.TrimSuffix(prefix, "/")
	a.prefix = prefix

	g := e.Group(prefix)

	g.POST("/signup", a.Signup())
	g.POST("/login", a.Login())
	g.POST("/logout", a.Logout())
	g.POST("/forgot-password", a.ForgotPassword())
	g.POST("/reset-password", a.ResetPassword())
	g.POST("/reset-password/verify", a.VerifyResetToken())
}
