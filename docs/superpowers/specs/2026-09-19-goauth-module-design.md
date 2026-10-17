# goauth — Reusable Authentication Module

**Module path:** `github.com/sbstnrmrz/goauth`
**Status:** built and merged to `main` on 2026-09-20. This document describes the module as it stands, not as it was first sketched; "Changed after approval" at the end records what moved and why.
**Scope of this spec:** the module only. Migrating `untitled-raffle-platform/api` to consume it is a separate piece of work with its own design.

## Goal

Extract the authentication code currently living in `untitled-raffle-platform/api/internal/auth` into a Go module that several of my own projects can import, so that session handling, password hashing and the password-reset flow exist in one audited place instead of being copied and diverging.

## Constraints that shape everything

The consuming projects all share one stack, and the module is allowed to depend on it directly:

- PostgreSQL, accessed through `pgx/v5` and `pgxpool`
- Echo **v5** (note `*echo.Context` is a pointer in v5, unlike v4)
- `sqlc` for query generation, `tern` for migrations
- `bcrypt` from `golang.org/x/crypto`

No router abstraction, no `database/sql` fallback, no storage interface. Those would be abstraction paid for with no buyer. If a future project uses a different router, that is the moment to reconsider, not now.

## What moves and what stays

**Moves into the module:**

| Area | Today |
|---|---|
| Password hashing | `HashPassword`, `CheckPassword` (`auth.go`) |
| Token generation | `generateToken`, `hashToken`, `resetTokenIdentifier` (`verification.go`) |
| Sessions | `createSession`, `setSessionCookie`, `clearSessionCookie` (`session.go`) |
| Context plumbing | `SetUserID`, `SetRole`, `UserIDFromContext`, `RoleFromContext` |
| Middleware | `RequireAuth`, `RequireRole` |
| Handlers | `Signup`, `Login`, `Logout`, `ChangePassword` |
| Password reset | `ForgotPassword`, `VerifyResetToken`, `ResetPassword`, `lookupResetToken`, `resetPasswordEmail` |

**Stays in each consuming project:**

- Queries over `users` that are not authentication: `GetUserByID`, `GetUsers`, `UpdateUserRole`, `UpdateUserImage`. These serve the admin panel, not the login flow.
- The policy that no endpoint may grant the `admin` role. That is the raffle platform's rule, enforced in its `internal/admin`, not a property of a generic auth library.
- Every application-specific public route. `/telegram/webhook` leaves the module entirely (see *Skipper*, below).

## Schema ownership

The module owns the DDL for `users`, `accounts`, `sessions` and `verifications`, but **does not apply migrations**. It publishes the DDL and the consuming project feeds it into its own `tern` chain:

```bash
go install github.com/sbstnrmrz/goauth/cmd/goauth@latest
goauth generate -o migrations/001_auth.sql
```

`-o` writes the file and creates its directory, so this works in a project that has no migration chain yet; without `-o` the DDL goes to stdout for piping. `-o` **refuses an existing file** and `-f` is the way through — see the accepted cost below for why that default is the safe one.

The generated file carries tern's `---- create above / drop below ----` marker and a header marking it generated. Today's migrations `001`–`005` collapse into this single file, with `role TEXT NOT NULL DEFAULT 'user'` present in `users` from the start rather than added by a later `ALTER`.

**Why this and not a `Migrate(ctx, pool)` that the module runs at boot**, keeping its own version table:

1. Consuming schemas have foreign keys into `users`. In the raffle platform, `customers.user_id` references `users(id)`, so the auth tables must be created earlier *in the same ordered chain*, not in a parallel track whose relative order is undefined.
2. `sqlc` needs the `users` DDL on a local path to type a join against `customers`. Pointing `sqlc.yaml` at the read-only, version-stamped module cache is fragile.

One migration tool — the one already in use.

**Accepted cost:** when the module changes its schema, the consumer regenerates the file *and hand-writes the corresponding `ALTER` migration*. The regenerated `001_auth.sql` must not be rewritten in place once applied; tern would not re-run it and the checked-in DDL would stop describing the live database. This is explicit and slightly awkward, which is the correct trade for schema changes — and it is why `generate -o` refuses an existing file rather than overwriting it. The likeliest file at a migration path is one already applied.

The module's own sqlc output lives in `authdb`. Consumers are not meant to import it — nothing in the public API exposes an `authdb` type — but the package is importable, so that is a convention rather than a compiler rule. Moving it to `internal/authdb` would make it enforced; see "Open questions".

## Package layout

```
goauth/
  go.mod                      module github.com/sbstnrmrz/goauth
  goauth.go                   Config, Auth, New
  password.go                 HashPassword, CheckPassword
  token.go                    generateToken, hashToken, resetTokenIdentifier
  session.go                  session creation, cookies, context keys
  middleware.go               RequireAuth, RequireRole
  handlers.go                 Signup, Login, Logout, ChangePassword
  reset.go                    ForgotPassword, VerifyResetToken, ResetPassword
  mount.go                    (*Auth).Mount
  email.go                    default reset-email copy
  schema.go                   Schema(), returning the embedded DDL
  authdb/                     generated by sqlc — never hand-edited
  queries/                    auth.sql, sessions.sql, verifications.sql
  schema/                     auth.sql — the owned DDL, embedded and sqlc's input
  cmd/goauth/                 the CLI: `goauth generate`
  sqlc.yaml
  README.md
```

The DDL lives in `schema/`, not `migrations/`: the module never migrates, and a `migrations/` directory inside it reads as if it did — confusing next to the consumer's real one. The directory is doing two jobs at once, which is why it is not simply embedded as a string: it is sqlc's `schema:` input as well as the published artifact, so the DDL that types `authdb` and the DDL a consumer applies cannot drift apart.

## Configuration

Everything that is a package-level `var` or a bare `os.Getenv` today becomes a field, validated once in `New`:

```go
type Config struct {
    Secure        bool          // Secure flag on the session cookie
    SessionTTL    time.Duration // default 7 * 24h
    ResetTokenTTL time.Duration // default 15m
    CookieName    string        // default "session_token"
    MinPassword   int           // default 8
    Mailer        Sender        // required only if the reset routes are mounted
    ResetURL      func(token string) string
    ResetEmail    func(name, link string, expiry time.Duration) (subject, text, html string)
    Skipper       func(c *echo.Context) bool
    OnSignup      func(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error
}

// DB is the pool seen through the methods this module needs: the three sqlc
// requires, plus Begin for the signup transaction. *pgxpool.Pool satisfies it,
// and so does pgxmock.PgxPoolIface, which is what keeps the handlers testable
// without a database. Taking *pgxpool.Pool here instead would make every test
// in this module require a live Postgres.
type DB interface {
    Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
    Query(context.Context, string, ...any) (pgx.Rows, error)
    QueryRow(context.Context, string, ...any) pgx.Row
    Begin(context.Context) (pgx.Tx, error)
}

func New(db DB, cfg Config) (*Auth, error)
```

Notes on the non-obvious fields:

- **`Secure`** replaces `var isProduction = os.Getenv("APP_ENV") == "production"`, which is read at package load and therefore cannot be varied by a test. As a field it is testable for free. The consumer passes `os.Getenv("APP_ENV") == "production"`.
- **`ResetURL`** replaces the hardcoded `FRONTEND_URL` + `/reset-password?token=` construction. The module still escapes the token; the consumer decides the host and path.
- **`ResetEmail`** exists because today's copy is English and hardcoded, while the raffle platform's front end is Spanish. A default in English ships with the module; a consumer that cares overrides it.
- **`Skipper`** replaces `publicPrefixes`. The module exempts its own mounted prefix on its own; anything else — `/telegram/webhook` in the raffle API — is the consumer's to declare. `Skipper` is Echo's own name for this shape.
- **`OnSignup`** runs inside the same transaction that creates the user and the account, before commit. A non-nil error rolls the whole signup back. The raffle platform will pass `nil` (signup deliberately creates no `customers` row), but without this hook the next project that needs to create a row alongside the user has to reimplement `Signup` entirely.

`New` returns an error rather than panicking, so a misconfiguration is fatal at boot in the consumer's own style.

## Public API

```go
a, err := goauth.New(pool, goauth.Config{ /* ... */ })   // pool is *pgxpool.Pool

a.Mount(e, "/auth")                // signup, login, logout, forgot/reset-password
e.Use(a.RequireAuth())
adminRoutes := e.Group("/admin", goauth.RequireRole("admin"))
users.PATCH("/me/password", a.ChangePassword())

userID, ok := goauth.UserIDFromContext(c)
role, ok := goauth.RoleFromContext(c)
```

`RequireRole` stays a free function — it reads the context and never touches the database. `Mount` registers the six auth routes under a prefix the consumer picks; the individual handlers stay exported for anyone who wants to wire them one by one.

`Mount` takes the prefix rather than a ready-made `*echo.Group` and creates the group itself, because Echo v5 does not expose a group's prefix — there is no `(*echo.Group).Prefix()` and the field is unexported, so a group handed in could not say what to exempt. The prefix it records is what `RequireAuth` exempts. This matters because Echo v5 applies `e.Use` middleware to every route regardless of registration order, so being registered first proves nothing — the exemption has to be explicit. A consumer that wires handlers individually instead of calling `Mount` has no recorded prefix and must exempt its own login routes through `Skipper`; `New` cannot detect that case, so it is documented rather than validated.

**The prefix exemption is boundary-checked**, and this is load-bearing rather than tidy. `RequireAuth` exempts a path only when it equals the mounted prefix or begins with the prefix plus `/`, so the cut always falls on a path separator rather than mid-word.

A bare `strings.HasPrefix` — which is what the original did, and what this module shipped until the final review caught it — exempts any sibling path that merely starts with the same characters. Mounted at `/user`, against the raffle platform's own routes:

| Path | `HasPrefix` | Boundary-checked |
|---|---|---|
| `/user` | exempt | exempt |
| `/user/login` | exempt | exempt |
| `/users/me/raffles` | **exempt** | needs a session |
| `/users/me/contacts` | **exempt** | needs a session |

The third and fourth rows are the whole point: an entire customer-facing tree served with no cookie, no session lookup and no role on the context. The original could get away with the loose check because its prefix list was a hardcoded pair one author had read; here the prefix is consumer-chosen and the module is the front door of several applications.

`Mount` also strips a trailing slash before recording the prefix, so `"/auth/"` and `"/auth"` behave identically — otherwise the `prefix+"/"` test would look for `//` and match nothing.

Behaviour is preserved exactly, including the parts that are deliberate and easy to "fix" by accident:

- `ForgotPassword` answers 204 whether or not the address exists, so it is not an account-enumeration oracle.
- `ResetPassword` claims the token with a row-count check *before* touching the password, and deletes every session for that user afterwards.
- `VerifyResetToken` takes the token in the body, not the query string, to keep it out of request logs.
- Reset email delivery runs detached with its own 30s timeout, because the request context dies with the response.
- Errors are `c.String` with a generic message; the cause goes to `slog.Error`.

## Testing

The existing tests (`auth_test.go`, `session_test.go`, `password_reset_test.go` — roughly 1050 lines) move across. They already mock the pool with `pgxmock/v5` rather than depending on the raffle schema, so they travel with import changes and the adjustments needed by `Config` replacing package-level state. The suite must be green with `go test ./...` in the new module, with no running database.

## Out of scope

- Migrating `untitled-raffle-platform/api` to consume the module.
- OAuth / social providers. The `accounts` table has the columns (`provider_id`, `access_token`, `refresh_token`, `scope`) but only `"credential"` is ever written today, and no consumer needs more.
- Email verification on signup, rate limiting, 2FA, refresh-token rotation.
- Tagging a release. `v0.1.0` can wait until a real consumer has compiled against it.

## Changed after approval

The design above was approved before implementation; these are the decisions that moved during it, each recorded so the reasoning is not lost.

- **`New` takes a `DB` interface, not `*pgxpool.Pool`.** The first draft took the pool. Every test in the module mocks with `pgxmock`, which is not a `*pgxpool.Pool`, so that signature would have required a live Postgres for every test. `DB` is the three methods sqlc needs plus `Begin`; `*pgxpool.Pool` and `pgxmock.PgxPoolIface` both satisfy it.
- **`Mount` takes `(e *echo.Echo, prefix string)`, not an `*echo.Group`.** Echo v5 exposes no `(*echo.Group).Prefix()` and the field is unexported, so a group handed in could not tell `RequireAuth` what to exempt.
- **`Signup` enforces `MinPassword`.** The original checked password length only on change, never on signup. This is the one behaviour that silently changes for the existing consumer: after migration, `POST /auth/signup` answers 400 for passwords it used to accept. Existing short passwords keep working for login and reset.
- **`ForgotPassword` guards a nil `Mailer`**, before the account lookup, so a misconfigured deployment does not write reset rows it can never deliver. The original could assume a mailer was present.
- **The DDL moved from `migrations/` to `schema/`**, and `cmd/authschema` became `cmd/goauth` with a `generate` subcommand, so `go install` yields a binary with a meaningful name rather than `authschema` or a generic `generate`.
- **The prefix exemption gained its boundary check** (see "Public API"). It shipped as a bare `strings.HasPrefix` and was caught in the final whole-branch review.
- **Ids are UUIDv7, not `BIGINT` identities** (2026-10-17). The first consumer, CuatroScore, exposes user ids in public URLs (`/profile/:id`), where a sequential id can be counted and walked. Every table keys on `UUID DEFAULT uuidv7()` and every id in the Go API is a `uuid.UUID`. That makes PostgreSQL 18 a requirement, and means a consumer still on `BIGINT` ids — the raffle API — migrates its keys before adopting the module.

## Open questions

Three decisions about the public API are deliberately unresolved. None blocks a consumer; each changes a signature or an import path, so they are cheaper to settle before the first one compiles against this.

1. **`Config.Secure` has the insecure value as its zero value.** A consumer who omits the field ships session cookies without the `Secure` attribute. The original could not fail this way: it read `APP_ENV` itself, so production was secure whether or not anyone thought about it. Renaming to `Insecure bool` would make the safe state the default, at the cost of reading oddly; a `slog.Warn` from `New` is the cheaper alternative, but it would fire on every development boot, where `false` is correct.
2. **`Mount` returns nothing**, so the auth routes cannot be given middleware of their own. Rate limiting `POST /auth/login` and `POST /auth/forgot-password` is the obvious next need, and today the only route to it is abandoning `Mount` and wiring the six handlers by hand — which also means taking over the prefix exemption through `Skipper`. Returning the `*echo.Group` it creates is additive and breaks no caller.
3. **`authdb` is importable** (see "Schema ownership"). `internal/authdb` would turn the convention into a compiler rule.
