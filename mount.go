package goauth

import "github.com/labstack/echo/v5"

// Mount creates a group at prefix, registers the authentication routes on it
// and records the prefix, which is what RequireAuth exempts. It takes the
// prefix rather than a ready-made *echo.Group because Echo v5 does not expose
// a group's prefix: there is no (*echo.Group).Prefix(), and the field is
// unexported, so a group handed in could not tell us what to exempt.
//
// A consumer that wires the handlers individually instead has no recorded
// prefix and must exempt its login routes through Config.Skipper.
func (a *Auth) Mount(e *echo.Echo, prefix string) {
	a.prefix = prefix
	e.Group(prefix)
}
