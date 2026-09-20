# goauth

Email-and-password authentication for Go services built on PostgreSQL, pgx/v5
and Echo v5: sessions in a cookie, bcrypt passwords, and a password reset flow
over email.

It is deliberately not a general-purpose library. It assumes that stack and
does not abstract over it.

## Install

```bash
go get github.com/sbstnrmrz/goauth
```

## Schema

goauth owns four tables — `users`, `accounts`, `sessions`, `verifications` —
but never applies migrations itself. Publish its DDL into your own chain:

```bash
go run github.com/sbstnrmrz/goauth/cmd/authschema > migrations/001_auth.sql
```

Apply it with your migration tool as usual. **Do not regenerate over a
migration you have already applied** — the tool will not re-run it, and the
checked-in DDL would stop describing the live database. When goauth changes its
schema, regenerate *and* hand-write the matching `ALTER` migration.

Your own tables may reference `users(id)`; that is why the DDL goes into your
chain rather than a separate one.

## Wiring

```go
a, err := goauth.New(pool, goauth.Config{
    Secure:   os.Getenv("APP_ENV") == "production",
    Mailer:   mailer,
    ResetURL: func(token string) string {
        return os.Getenv("FRONTEND_URL") + "/reset-password?token=" + token
    },
    Skipper: func(c *echo.Context) bool {
        return strings.HasPrefix(c.Request().URL.Path, "/webhooks/")
    },
})
if err != nil {
    log.Fatal(err)
}

a.Mount(e, "/auth")
e.Use(a.RequireAuth())

admin := e.Group("/admin", goauth.RequireRole("admin"))
e.PATCH("/users/me/password", a.ChangePassword())
```

`Mount` registers `POST /auth/signup`, `/login`, `/logout`,
`/forgot-password`, `/reset-password` and `/reset-password/verify`, and records
its prefix so `RequireAuth` exempts it. Everything else you need public goes
through `Config.Skipper`, and each such route must carry its own
authentication — `RequireAuth` will not be looking.

In handlers:

```go
userID, ok := goauth.UserIDFromContext(c)
role, ok := goauth.RoleFromContext(c)
```

## Configuration

| Field | Default | Notes |
|---|---|---|
| `Secure` | `false` | `Secure` flag on the session cookie |
| `SessionTTL` | 7 days | |
| `ResetTokenTTL` | 15 minutes | |
| `CookieName` | `session_token` | |
| `MinPassword` | 8 | signup, change and reset |
| `Mailer` | none | required for the reset routes |
| `ResetURL` | **required** | builds the emailed link |
| `ResetEmail` | English copy | override for another language |
| `Skipper` | none | your own public routes |
| `OnSignup` | none | runs in the signup transaction |

## What it deliberately does not do

- Grant roles. `RequireRole` reads `users.role`; writing it is your
  application's decision, and keeping that out of here is intentional.
- OAuth. The `accounts` table has the columns, but only `provider_id =
  'credential'` is ever written.
- Email verification on signup, rate limiting, 2FA, refresh-token rotation.

## Behaviour worth knowing

- `POST /auth/forgot-password` answers `204` whether or not the address is
  registered, so it cannot be used to discover which emails have accounts.
- A reset token is single-use and claimed before the password is touched, so a
  failure mid-flow spends the token rather than leaving it replayable.
- Redeeming a reset deletes every session for that user, on the assumption a
  reset may be recovery from a compromise.
- `POST /auth/signup` does **not** sign the new user in.
