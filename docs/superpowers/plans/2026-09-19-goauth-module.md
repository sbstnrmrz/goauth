# goauth Module Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `github.com/sbstnrmrz/goauth`, a reusable Go module holding the authentication code currently in `untitled-raffle-platform/api/internal/auth`, so session handling, password hashing and password reset live in one place across several projects.

**Architecture:** A single root package `goauth` exposing an `Auth` value built by `New(db DB, cfg Config)`, with sqlc-generated queries hidden in an internal `authdb` subpackage. Everything that is a package-level `var` or a bare `os.Getenv` in the original becomes a validated `Config` field. The module owns the DDL for `users`, `accounts`, `sessions` and `verifications` and publishes it through `cmd/authschema` for the consumer's own tern chain — it never applies migrations itself.

**Tech Stack:** Go 1.26.7, Echo v5 (`github.com/labstack/echo/v5`), pgx/v5, sqlc v1.31.1, bcrypt (`golang.org/x/crypto`), pgxmock/v5 for tests.

**Spec:** `docs/superpowers/specs/2026-09-19-goauth-module-design.md`

## Global Constraints

- **Repo:** all work happens in `~/dev/go-auth`, which is already a git repo with one commit (the spec). Every command runs from that root.
- **Module path:** `github.com/sbstnrmrz/goauth`. Package name `goauth`.
- **Go version:** `go 1.26.7` in `go.mod`, matching the source project.
- **Echo v5, not v4.** The context is a **pointer**: handlers are `func(c *echo.Context) error`. Writing `echo.Context` by value will not compile.
- **The source of truth for behaviour** is `~/dev/untitled-raffle-platform/api/internal/auth/*.go`. Read the original file before porting it. Behaviour must be preserved exactly; this is a move plus a configuration refactor, not a rewrite.
- **No database in tests.** Every test mocks with `pgxmock.NewPool()`. `go test ./...` must pass with nothing running.
- **Never hand-edit `authdb/`.** It is sqlc output. Change `queries/*.sql` or `migrations/auth.sql` and regenerate.
- **Errors:** `c.String(status, "generic message")` to the caller, `slog.Error` for the cause. Never leak a database error into a response body.
- **Comments in English** in this module (unlike the raffle API, which is mixed). It is a public library.
- **Commit after every task.** Messages use the `feat:` / `test:` / `docs:` / `chore:` prefixes already used in the source repo.

---

## File Structure

| File | Responsibility |
|---|---|
| `go.mod`, `go.sum` | module definition |
| `sqlc.yaml` | sqlc config pointing at `queries/` and `migrations/` |
| `migrations/auth.sql` | the owned DDL: `users`, `accounts`, `sessions`, `verifications` |
| `queries/auth.sql` | account + user queries auth itself needs |
| `queries/sessions.sql` | session CRUD |
| `queries/verifications.sql` | reset-token rows |
| `authdb/` | sqlc output — generated, never hand-edited |
| `cmd/authschema/main.go` | prints the embedded DDL to stdout |
| `goauth.go` | `DB`, `Sender`, `Config`, `Auth`, `New` |
| `password.go` | `HashPassword`, `CheckPassword` |
| `token.go` | `generateToken`, `hashToken`, `resetTokenIdentifier` |
| `session.go` | session creation, cookie set/clear, context keys and accessors |
| `middleware.go` | `RequireAuth`, `RequireRole` |
| `handlers.go` | `Signup`, `Login`, `Logout`, `ChangePassword` |
| `reset.go` | `ForgotPassword`, `VerifyResetToken`, `ResetPassword`, `lookupResetToken` |
| `email.go` | `defaultResetEmail` |
| `mount.go` | `(*Auth).Mount` |
| `README.md` | how a consumer wires it up |

---

### Task 1: Module skeleton, schema and generated queries

Nothing in this module compiles until `authdb` exists, so this task produces it. There is no TDD cycle here — the deliverable is generated code plus a test that proves the generation is real.

**Files:**
- Create: `go.mod`, `sqlc.yaml`, `migrations/auth.sql`, `queries/auth.sql`, `queries/sessions.sql`, `queries/verifications.sql`
- Create (generated): `authdb/db.go`, `authdb/models.go`, `authdb/auth.sql.go`, `authdb/sessions.sql.go`, `authdb/verifications.sql.go`
- Test: `authdb_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: package `github.com/sbstnrmrz/goauth/authdb` with `authdb.DBTX`, `authdb.New(DBTX) *Queries`, `(*Queries).WithTx(pgx.Tx) *Queries`, the row structs `User`, `Account`, `Session`, `Verification`, and the methods `CreateUser`, `GetUserByID`, `CreateAccount`, `GetAccountByEmail`, `GetAccountByUserID`, `UpdateAccountPassword`, `CreateSession`, `GetSessionByToken`, `DeleteSession`, `DeleteSessionsByUserID`, `CreateVerification`, `GetVerificationByIdentifier`, `DeleteVerification`, `DeleteUserResetTokens`.

- [ ] **Step 1: Initialise the module**

```bash
cd ~/dev/go-auth
go mod init github.com/sbstnrmrz/goauth
```

Then edit `go.mod` so the version line reads exactly `go 1.26.7`.

- [ ] **Step 2: Write the DDL**

Create `migrations/auth.sql`. This is the four migrations `001`–`005` of the source repo collapsed into one, with `role` present in `users` from the start instead of added by a later `ALTER`:

```sql
-- Code generated by github.com/sbstnrmrz/goauth. DO NOT EDIT.
--
-- Regenerate with:
--     go run github.com/sbstnrmrz/goauth/cmd/authschema > migrations/001_auth.sql
--
-- Once this file has been applied, do NOT regenerate over it: tern will not
-- re-run an applied migration, so the checked-in DDL would stop describing the
-- live database. A schema change in goauth means regenerating AND hand-writing
-- the matching ALTER migration.

CREATE TABLE users (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    image TEXT,
    role TEXT NOT NULL DEFAULT 'user',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE accounts (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id BIGINT NOT NULL,
    provider_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    password TEXT,
    access_token TEXT,
    refresh_token TEXT,
    access_token_expires_at TIMESTAMPTZ,
    refresh_token_expires_at TIMESTAMPTZ,
    scope TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    CONSTRAINT fk_account_user
        FOREIGN KEY (user_id)
        REFERENCES users (id)
        ON DELETE CASCADE
);

CREATE INDEX accounts_user_id_idx ON accounts (user_id);

CREATE TABLE sessions (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    token TEXT NOT NULL UNIQUE,
    user_id BIGINT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    CONSTRAINT fk_session_user
        FOREIGN KEY (user_id)
        REFERENCES users (id)
        ON DELETE CASCADE
);

CREATE INDEX sessions_user_id_idx ON sessions (user_id);

CREATE TABLE verifications (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    identifier TEXT NOT NULL UNIQUE,
    value TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX verifications_value_idx ON verifications (value);

---- create above / drop below ----

DROP TABLE verifications;
DROP TABLE sessions;
DROP TABLE accounts;
DROP TABLE users;
```

Note the drop order: `accounts` and `sessions` reference `users`, so `users` goes last.

- [ ] **Step 3: Write the queries**

Create `queries/auth.sql`. Only what authentication itself needs — `GetUsers`, `UpdateUserRole` and `UpdateUserImage` from the source repo stay behind in the consumer, per the spec:

```sql
-- name: CreateUser :one
INSERT INTO users (name, email, image)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM users
WHERE id = $1;

-- name: CreateAccount :one
INSERT INTO accounts (user_id, provider_id, account_id, password)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetAccountByEmail :one
SELECT * FROM accounts
WHERE account_id = $1 AND provider_id = $2;

-- name: GetAccountByUserID :one
SELECT * FROM accounts
WHERE user_id = $1 AND provider_id = $2;

-- name: UpdateAccountPassword :exec
UPDATE accounts
SET password = $1, updated_at = now()
WHERE user_id = $2 AND provider_id = $3;
```

Create `queries/sessions.sql`:

```sql
-- name: CreateSession :one
INSERT INTO sessions (token, user_id, expires_at, ip_address, user_agent)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetSessionByToken :one
SELECT sqlc.embed(sessions), users.role FROM sessions
JOIN users ON users.id = sessions.user_id
WHERE sessions.token = $1;

-- name: DeleteSession :exec
DELETE FROM sessions
WHERE token = $1;

-- name: DeleteSessionsByUserID :exec
DELETE FROM sessions
WHERE user_id = $1;
```

Create `queries/verifications.sql`:

```sql
-- name: CreateVerification :one
INSERT INTO verifications (identifier, value, expires_at)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetVerificationByIdentifier :one
SELECT * FROM verifications
WHERE identifier = $1;

-- name: DeleteVerification :execrows
DELETE FROM verifications
WHERE identifier = $1;

-- name: DeleteUserResetTokens :exec
DELETE FROM verifications
WHERE value = $1 AND identifier LIKE 'password-reset:%';
```

`DeleteVerification` is `:execrows`, not `:exec` — `ResetPassword` uses the returned row count to claim the token atomically. Getting this wrong silently breaks single-use tokens.

- [ ] **Step 4: Write the sqlc config**

Create `sqlc.yaml`:

```yaml
version: "2"
sql:
  - engine: "postgresql"
    queries: "queries"
    schema: "migrations"
    gen:
      go:
        package: "authdb"
        out: "authdb"
        sql_package: "pgx/v5"
        emit_json_tags: true
```

- [ ] **Step 5: Generate**

```bash
cd ~/dev/go-auth && sqlc generate && go mod tidy
```

Expected: `authdb/` now holds `db.go`, `models.go`, `auth.sql.go`, `sessions.sql.go`, `verifications.sql.go`. If sqlc reports a parse error, the DDL and the queries disagree — fix the SQL, never the generated Go.

- [ ] **Step 6: Write a test that the generated layer is wired correctly**

Create `authdb_test.go` in the root package directory but declaring `package goauth_test`... actually place it at `authdb/queries_test.go` with `package authdb`:

```go
package authdb

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/pashagolub/pgxmock/v5"
)

// TestGetSessionByToken_EmbedsSessionAndRole guards the one query whose shape
// is not obvious: it joins users to carry the role alongside the session, and
// RequireAuth depends on both halves arriving.
func TestGetSessionByToken_EmbedsSessionAndRole(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	expiresAt := time.Now().Add(time.Hour)

	mock.ExpectQuery("SELECT sessions.id").
		WithArgs("tok").
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "token", "user_id", "expires_at", "ip_address",
			"user_agent", "created_at", "updated_at", "role",
		}).AddRow(
			int64(1), "tok", int64(7),
			pgtype.Timestamptz{Time: expiresAt, Valid: true},
			pgtype.Text{}, pgtype.Text{},
			pgtype.Timestamptz{}, pgtype.Timestamptz{}, "admin",
		))

	row, err := New(mock).GetSessionByToken(context.Background(), "tok")
	if err != nil {
		t.Fatalf("GetSessionByToken returned error: %v", err)
	}

	if row.Session.UserID != 7 {
		t.Fatalf("expected user id 7, got %d", row.Session.UserID)
	}

	if row.Role != "admin" {
		t.Fatalf("expected role %q, got %q", "admin", row.Role)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
```

- [ ] **Step 7: Run the test**

```bash
cd ~/dev/go-auth && go test ./authdb/ -run TestGetSessionByToken -v
```

Expected: PASS. If it fails on the field name `row.Session`, check what sqlc named the embedded struct in `authdb/sessions.sql.go` and use that name — `sqlc.embed` names it after the table.

- [ ] **Step 8: Commit**

```bash
cd ~/dev/go-auth
git add go.mod go.sum sqlc.yaml migrations/ queries/ authdb/
git commit -m "feat: module skeleton, owned schema and generated queries"
```

---

### Task 2: Password hashing and tokens

The two leaf files: no database, no Echo, no config. Pure functions ported unchanged from `auth.go` and `verification.go`.

**Files:**
- Create: `password.go`, `token.go`
- Test: `password_test.go`, `token_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `HashPassword(plain string) (string, error)`, `CheckPassword(plain, hash string) error`, and the unexported `generateToken() (string, error)`, `hashToken(token string) string`, `resetTokenIdentifier(token string) string`.

- [ ] **Step 1: Write the failing tests**

Create `password_test.go`:

```go
package goauth

import "testing"

func TestHashPassword_RoundTrips(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}

	if hash == "correct horse battery staple" {
		t.Fatal("hash is the plaintext")
	}

	if err := CheckPassword("correct horse battery staple", hash); err != nil {
		t.Fatalf("CheckPassword rejected the right password: %v", err)
	}
}

func TestCheckPassword_RejectsWrongPassword(t *testing.T) {
	hash, err := HashPassword("right")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}

	if err := CheckPassword("wrong", hash); err == nil {
		t.Fatal("CheckPassword accepted the wrong password")
	}
}

// bcrypt salts, so the same password hashes differently every time. A test
// asserting a fixed digest would pass only by accident.
func TestHashPassword_IsSalted(t *testing.T) {
	first, err := HashPassword("same")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}

	second, err := HashPassword("same")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}

	if first == second {
		t.Fatal("two hashes of the same password are identical, so it is unsalted")
	}
}
```

Create `token_test.go`:

```go
package goauth

import (
	"strings"
	"testing"
)

func TestGenerateToken_IsRandomAndURLSafe(t *testing.T) {
	first, err := generateToken()
	if err != nil {
		t.Fatalf("generateToken returned error: %v", err)
	}

	second, err := generateToken()
	if err != nil {
		t.Fatalf("generateToken returned error: %v", err)
	}

	if first == second {
		t.Fatal("two tokens are identical")
	}

	// 256 bits in base64url without padding is 43 characters.
	if len(first) != 43 {
		t.Fatalf("expected a 43-character token, got %d: %q", len(first), first)
	}

	if strings.ContainsAny(first, "+/=") {
		t.Fatalf("token is not URL-safe: %q", first)
	}
}

func TestHashToken_IsStableAndNotThePlaintext(t *testing.T) {
	if hashToken("tok") != hashToken("tok") {
		t.Fatal("hashToken is not stable")
	}

	if hashToken("tok") == "tok" {
		t.Fatal("hashToken returned the plaintext")
	}

	if hashToken("tok") == hashToken("other") {
		t.Fatal("two different tokens share a digest")
	}
}

// The stored identifier must carry the prefix DeleteUserResetTokens matches on
// with LIKE 'password-reset:%', and must never contain the raw token.
func TestResetTokenIdentifier_IsPrefixedAndHashed(t *testing.T) {
	identifier := resetTokenIdentifier("tok")

	if !strings.HasPrefix(identifier, "password-reset:") {
		t.Fatalf("identifier lacks the prefix: %q", identifier)
	}

	if strings.Contains(identifier, "tok") {
		t.Fatalf("identifier leaks the raw token: %q", identifier)
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

```bash
cd ~/dev/go-auth && go test . -run 'TestHashPassword|TestCheckPassword|TestGenerateToken|TestHashToken|TestResetTokenIdentifier' -v
```

Expected: FAIL to build, with `undefined: HashPassword` and friends.

- [ ] **Step 3: Write the implementation**

Create `password.go`:

```go
package goauth

import "golang.org/x/crypto/bcrypt"

// HashPassword returns a bcrypt digest of plain, salted by bcrypt itself.
func HashPassword(plain string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// CheckPassword reports whether plain is the password behind hash. A non-nil
// error means it is not; callers must not distinguish the reasons in what they
// tell the caller.
func CheckPassword(plain, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain))
}
```

Create `token.go`:

```go
package goauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

const resetTokenPrefix = "password-reset:"

// generateToken returns a URL-safe, 256-bit random token.
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// hashToken derives the value stored in the database for a token. Tokens carry
// 256 bits of entropy, so a fast digest is enough here - unlike passwords, they
// are not guessable and do not need a slow KDF.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// resetTokenIdentifier is the verifications.identifier for a password reset
// token. Only the hash is ever stored, so a database leak cannot be replayed.
func resetTokenIdentifier(token string) string {
	return resetTokenPrefix + hashToken(token)
}
```

- [ ] **Step 4: Run the tests**

```bash
cd ~/dev/go-auth && go test . -v && go mod tidy
```

Expected: PASS, all six tests.

- [ ] **Step 5: Commit**

```bash
cd ~/dev/go-auth
git add password.go token.go password_test.go token_test.go go.mod go.sum
git commit -m "feat: password hashing and reset tokens"
```

---

### Task 3: Config, DB and New

The spine the rest of the module hangs off. This is where the package-level `var isProduction = os.Getenv("APP_ENV") == "production"` of the original dies.

**Files:**
- Create: `goauth.go`
- Test: `goauth_test.go`

**Interfaces:**
- Consumes: `authdb` from Task 1.
- Produces:
  - `type DB interface { Exec(context.Context, string, ...any) (pgconn.CommandTag, error); Query(context.Context, string, ...any) (pgx.Rows, error); QueryRow(context.Context, string, ...any) pgx.Row; Begin(context.Context) (pgx.Tx, error) }`
  - `type Sender interface { Send(ctx context.Context, to, subject, plainText, html string) error }`
  - `type Config struct { Secure bool; SessionTTL, ResetTokenTTL time.Duration; CookieName string; MinPassword int; Mailer Sender; ResetURL func(token string) string; ResetEmail func(name, link string, expiry time.Duration) (string, string, string); Skipper func(c *echo.Context) bool; OnSignup func(ctx context.Context, tx pgx.Tx, userID int64) error }`
  - `type Auth struct` with unexported fields `db DB`, `q *authdb.Queries`, `cfg Config`, `prefix string`
  - `func New(db DB, cfg Config) (*Auth, error)`

- [ ] **Step 1: Write the failing tests**

Create `goauth_test.go`:

```go
package goauth

import (
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v5"
)

func TestNew_AppliesDefaults(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	a, err := New(mock, Config{ResetURL: func(string) string { return "" }})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	if a.cfg.SessionTTL != 7*24*time.Hour {
		t.Fatalf("expected the default session TTL, got %v", a.cfg.SessionTTL)
	}

	if a.cfg.ResetTokenTTL != 15*time.Minute {
		t.Fatalf("expected the default reset TTL, got %v", a.cfg.ResetTokenTTL)
	}

	if a.cfg.CookieName != "session_token" {
		t.Fatalf("expected the default cookie name, got %q", a.cfg.CookieName)
	}

	if a.cfg.MinPassword != 8 {
		t.Fatalf("expected the default minimum password length, got %d", a.cfg.MinPassword)
	}

	if a.cfg.ResetEmail == nil {
		t.Fatal("expected a default reset email builder")
	}
}

func TestNew_KeepsExplicitValues(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	a, err := New(mock, Config{
		SessionTTL:    time.Hour,
		ResetTokenTTL: time.Minute,
		CookieName:    "sid",
		MinPassword:   12,
		Secure:        true,
		ResetURL:      func(string) string { return "" },
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	if a.cfg.SessionTTL != time.Hour || a.cfg.CookieName != "sid" || a.cfg.MinPassword != 12 || !a.cfg.Secure {
		t.Fatalf("New overwrote explicit configuration: %+v", a.cfg)
	}
}

func TestNew_RejectsNilDB(t *testing.T) {
	if _, err := New(nil, Config{ResetURL: func(string) string { return "" }}); err == nil {
		t.Fatal("New accepted a nil DB")
	}
}

// ResetURL has no sensible default: only the consumer knows its front end's
// host and route, and a wrong guess emails people a dead link.
func TestNew_RejectsMissingResetURL(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	if _, err := New(mock, Config{}); err == nil {
		t.Fatal("New accepted a Config without ResetURL")
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

```bash
cd ~/dev/go-auth && go test . -run TestNew -v
```

Expected: FAIL to build, `undefined: New`, `undefined: Config`.

- [ ] **Step 3: Write the implementation**

Create `goauth.go`:

```go
package goauth

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/labstack/echo/v5"

	"github.com/sbstnrmrz/goauth/authdb"
)

// DB is the pool seen through the methods this module needs: the three sqlc
// requires, plus Begin for the signup transaction. *pgxpool.Pool satisfies it,
// and so does pgxmock.PgxPoolIface, which is what keeps every handler here
// testable without a database.
type DB interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Begin(context.Context) (pgx.Tx, error)
}

// Sender is the subset of a mailer that password reset depends on, so it can be
// tested without an SMTP server.
type Sender interface {
	Send(ctx context.Context, to, subject, plainText, html string) error
}

// Config holds everything the original package kept in package-level vars and
// os.Getenv calls. As fields they are testable and differ per consumer.
type Config struct {
	// Secure sets the Secure flag on the session cookie. Consumers typically
	// pass os.Getenv("APP_ENV") == "production".
	Secure bool

	// SessionTTL defaults to 7 days, ResetTokenTTL to 15 minutes.
	SessionTTL    time.Duration
	ResetTokenTTL time.Duration

	// CookieName defaults to "session_token".
	CookieName string

	// MinPassword is the shortest password accepted on signup, change and
	// reset. Defaults to 8.
	MinPassword int

	// Mailer delivers the password reset email. Required only if the reset
	// routes are mounted; ForgotPassword answers 500 without it.
	Mailer Sender

	// ResetURL builds the link emailed to a user, given a raw token. Required:
	// only the consumer knows its front end. The token is URL-escaped already.
	ResetURL func(token string) string

	// ResetEmail builds the reset message. Defaults to English copy; override
	// it for another language or to match a house style.
	ResetEmail func(name, link string, expiry time.Duration) (subject, text, html string)

	// Skipper exempts a request from RequireAuth. The module exempts its own
	// mounted prefix on its own; this is for the consumer's public routes.
	Skipper func(c *echo.Context) bool

	// OnSignup runs inside the transaction that creates the user and account,
	// before commit. A non-nil error rolls the whole signup back.
	OnSignup func(ctx context.Context, tx pgx.Tx, userID int64) error
}

// Auth is the configured module. Build it with New and keep one per process.
type Auth struct {
	db  DB
	q   *authdb.Queries
	cfg Config

	// prefix is recorded by Mount and is what RequireAuth exempts.
	prefix string
}

// New validates cfg, fills its defaults and returns the configured Auth.
func New(db DB, cfg Config) (*Auth, error) {
	if db == nil {
		return nil, errors.New("goauth: DB is required")
	}

	if cfg.ResetURL == nil {
		return nil, errors.New("goauth: Config.ResetURL is required")
	}

	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 7 * 24 * time.Hour
	}

	if cfg.ResetTokenTTL <= 0 {
		cfg.ResetTokenTTL = 15 * time.Minute
	}

	if cfg.CookieName == "" {
		cfg.CookieName = "session_token"
	}

	if cfg.MinPassword <= 0 {
		cfg.MinPassword = 8
	}

	if cfg.ResetEmail == nil {
		cfg.ResetEmail = defaultResetEmail
	}

	return &Auth{db: db, q: authdb.New(db), cfg: cfg}, nil
}
```

- [ ] **Step 4: Add the default email builder so the package compiles**

Create `email.go`. This is the copy from the original `resetPasswordEmail`, with the hardcoded `FRONTEND_URL` construction removed — the link arrives already built:

```go
package goauth

import (
	"fmt"
	"time"
)

// defaultResetEmail builds the reset message, returning subject, plain text and
// HTML bodies. Override Config.ResetEmail to change the copy or its language.
func defaultResetEmail(name, link string, expiry time.Duration) (string, string, string) {
	minutes := int(expiry.Minutes())

	subject := "Reset your password"

	text := fmt.Sprintf(`Hi %s,

We received a request to reset your password. Open the link below to choose a new one:

%s

This link expires in %d minutes and can only be used once.

If you didn't request a password reset, you can ignore this email - your password will stay the same.`, name, link, minutes)

	html := fmt.Sprintf(`<p>Hi %s,</p>
<p>We received a request to reset your password. Click the link below to choose a new one:</p>
<p><a href="%s">Reset your password</a></p>
<p>This link expires in %d minutes and can only be used once.</p>
<p>If you didn't request a password reset, you can ignore this email &mdash; your password will stay the same.</p>`, name, link, minutes)

	return subject, text, html
}
```

- [ ] **Step 5: Run the tests**

```bash
cd ~/dev/go-auth && go test . -v && go mod tidy
```

Expected: PASS, including the Task 2 tests.

- [ ] **Step 6: Commit**

```bash
cd ~/dev/go-auth
git add goauth.go email.go goauth_test.go go.mod go.sum
git commit -m "feat: Config, DB and New"
```

---

### Task 4: Sessions, cookies and request context

Ported from `session.go`, with `sessionCookieName`, `sessionDuration` and `isProduction` replaced by `a.cfg`.

**Files:**
- Create: `session.go`
- Test: `session_test.go`
- Reference: `~/dev/untitled-raffle-platform/api/internal/auth/session.go`

**Interfaces:**
- Consumes: `Auth`, `Config` (Task 3); `generateToken` (Task 2); `authdb.CreateSessionParams` (Task 1).
- Produces: `(a *Auth) createSession(c *echo.Context, userID int64) (authdb.Session, error)`, `(a *Auth) setSessionCookie(c *echo.Context, token string, expiresAt time.Time)`, `(a *Auth) clearSessionCookie(c *echo.Context)`, and the exported `SetUserID(c *echo.Context, userID int64)`, `SetRole(c *echo.Context, role string)`, `UserIDFromContext(c *echo.Context) (int64, bool)`, `RoleFromContext(c *echo.Context) (string, bool)`.

- [ ] **Step 1: Write the failing tests**

Create `session_test.go`:

```go
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
```

- [ ] **Step 2: Run them to verify they fail**

```bash
cd ~/dev/go-auth && go test . -run 'TestSetSessionCookie|TestClearSessionCookie|TestCreateSession|TestContextAccessors' -v
```

Expected: FAIL to build, `a.setSessionCookie undefined`, `undefined: SetUserID`.

- [ ] **Step 3: Write the implementation**

Create `session.go`:

```go
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
```

- [ ] **Step 4: Run the tests**

```bash
cd ~/dev/go-auth && go test . -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd ~/dev/go-auth
git add session.go session_test.go
git commit -m "feat: sessions, cookies and request context"
```

---

### Task 5: RequireAuth and RequireRole

Ported from `session.go`, with `publicPrefixes` replaced by the recorded mount prefix plus `Config.Skipper`. This is the task where behaviour genuinely changes shape, so read the original's comment on `publicPrefixes` before starting.

**Files:**
- Create: `middleware.go`
- Test: `middleware_test.go`
- Reference: `~/dev/untitled-raffle-platform/api/internal/auth/session.go:113-172`

**Interfaces:**
- Consumes: `Auth` (Task 3); `SetUserID`, `SetRole`, `RoleFromContext` (Task 4).
- Produces: `(a *Auth) RequireAuth() echo.MiddlewareFunc`, `(a *Auth) isPublic(c *echo.Context) bool`, `RequireRole(roles ...string) echo.MiddlewareFunc`.

- [ ] **Step 1: Write the failing tests**

Create `middleware_test.go`:

```go
package goauth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
```

The imports this file needs: `errors`, `net/http`, `net/http/httptest`, `testing`, `time`, `github.com/jackc/pgx/v5`, `github.com/labstack/echo/v5`, `github.com/pashagolub/pgxmock/v5`.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd ~/dev/go-auth && go test . -run 'TestRequireAuth|TestRequireRole' -v
```

Expected: FAIL to build, `a.RequireAuth undefined`, `a.Mount undefined`, `undefined: RequireRole`.

- [ ] **Step 3: Write the implementation**

Create `middleware.go`:

```go
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
	if a.prefix != "" && strings.HasPrefix(c.Request().URL.Path, a.prefix) {
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
```

- [ ] **Step 4: Add a stub Mount so the package compiles**

`TestRequireAuth_SkipsMountedPrefix` needs `Mount` to exist. Create `mount.go` with the prefix recording only; Task 8 fills in the routes:

```go
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
```

- [ ] **Step 5: Run the tests**

```bash
cd ~/dev/go-auth && go test . -v
```

Expected: PASS, all tests from Tasks 2-5.

- [ ] **Step 6: Commit**

```bash
cd ~/dev/go-auth
git add middleware.go mount.go middleware_test.go
git commit -m "feat: RequireAuth and RequireRole, with the public-route list replaced by a Skipper"
```

---

### Task 6: Signup, Login, Logout and ChangePassword

Ported from `handlers.go` and `auth.go`. `Signup` gains the `OnSignup` hook.

**Files:**
- Create: `handlers.go`
- Test: `handlers_test.go`
- Reference: `~/dev/untitled-raffle-platform/api/internal/auth/handlers.go`, `.../auth.go:26-86`

**Interfaces:**
- Consumes: `Auth` (Task 3); `HashPassword`, `CheckPassword` (Task 2); `createSession`, `clearSessionCookie`, `UserIDFromContext` (Task 4).
- Produces: `(a *Auth) Signup() echo.HandlerFunc`, `(a *Auth) Login() echo.HandlerFunc`, `(a *Auth) Logout() echo.HandlerFunc`, `(a *Auth) ChangePassword() echo.HandlerFunc`, and the request types `SignupRequest{Name, Email, Password, Image string}`, `LoginRequest{Email, Password string}`, `ChangePasswordRequest{CurrentPassword, NewPassword string}`.

- [ ] **Step 1: Write the failing tests**

Create `handlers_test.go`. Port the eight `TestChangePassword_*` cases from `~/dev/untitled-raffle-platform/api/internal/auth/auth_test.go` verbatim, adjusting only the construction (`a := newAuth(t, mock, Config{})` then `a.ChangePassword()` instead of `ChangePassword(models.New(mock))`) and the row helper. Add to them the cases below, which cover what the original did not:

```go
func accountRow(userID int64, hashedPassword string) *pgxmock.Rows {
	return pgxmock.NewRows([]string{
		"id", "user_id", "provider_id", "account_id", "password",
		"access_token", "refresh_token", "access_token_expires_at",
		"refresh_token_expires_at", "scope", "created_at", "updated_at",
	}).AddRow(
		int64(1), userID, "credential", "user@example.test",
		pgtype.Text{String: hashedPassword, Valid: true},
		pgtype.Text{}, pgtype.Text{},
		pgtype.Timestamptz{}, pgtype.Timestamptz{},
		pgtype.Text{}, pgtype.Timestamptz{}, pgtype.Timestamptz{},
	)
}

func userRow(id int64, name, email, role string) *pgxmock.Rows {
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
		WillReturnRows(accountRow(7, hashed))

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
		WillReturnRows(accountRow(7, hashed))
	mock.ExpectQuery("SELECT (.+) FROM users").
		WithArgs(int64(7)).
		WillReturnRows(userRow(7, "User", "user@example.test", "user"))
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
		WillReturnRows(userRow(7, "User", "user@example.test", "user"))
	mock.ExpectQuery("INSERT INTO accounts").
		WithArgs(int64(7), "credential", "user@example.test", pgxmock.AnyArg()).
		WillReturnRows(accountRow(7, "hashed"))
	mock.ExpectRollback()

	a := newAuth(t, mock, Config{
		OnSignup: func(ctx context.Context, tx pgx.Tx, userID int64) error {
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
```

- [ ] **Step 2: Run them to verify they fail**

```bash
cd ~/dev/go-auth && go test . -run 'TestLogin|TestSignup|TestLogout|TestChangePassword' -v
```

Expected: FAIL to build, `a.Signup undefined`, `a.Login undefined`, `a.Logout undefined`, `a.ChangePassword undefined`.

- [ ] **Step 3: Write the implementation**

Create `handlers.go`:

```go
package goauth

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v5"

	"github.com/sbstnrmrz/goauth/authdb"
)

// credentialProvider is the accounts.provider_id for email and password. The
// table carries the columns an OAuth provider would need, but nothing writes
// another value today.
const credentialProvider = "credential"

type SignupRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Image    string `json:"image"`
}

// Signup creates a user and its credential account in one transaction, then
// runs Config.OnSignup inside that same transaction so a consumer can add its
// own rows. It deliberately does not sign the new user in.
func (a *Auth) Signup() echo.HandlerFunc {
	return func(c *echo.Context) error {
		var req SignupRequest
		if err := c.Bind(&req); err != nil {
			return c.String(http.StatusBadRequest, "invalid request body")
		}

		if req.Name == "" || req.Email == "" || req.Password == "" {
			return c.String(http.StatusBadRequest, "name, email and password are required")
		}

		// Validate before opening the transaction, so a doomed request never
		// needs a rollback.
		if len(req.Password) < a.cfg.MinPassword {
			return c.String(http.StatusBadRequest,
				fmt.Sprintf("password must be at least %d characters", a.cfg.MinPassword))
		}

		ctx := c.Request().Context()

		hashed, err := HashPassword(req.Password)
		if err != nil {
			slog.Error("failed to hash password", "error", err)
			return c.String(http.StatusInternalServerError, "failed to create user")
		}

		tx, err := a.db.Begin(ctx)
		if err != nil {
			slog.Error("failed to begin transaction", "error", err)
			return c.String(http.StatusInternalServerError, "failed to create user")
		}
		defer tx.Rollback(ctx)

		qtx := authdb.New(tx)

		user, err := qtx.CreateUser(ctx, authdb.CreateUserParams{
			Name:  req.Name,
			Email: req.Email,
			Image: pgtype.Text{String: req.Image, Valid: req.Image != ""},
		})
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return c.String(http.StatusConflict, "email is already in use")
			}
			slog.Error("failed to create user", "error", err)
			return c.String(http.StatusInternalServerError, "failed to create user")
		}

		if _, err := qtx.CreateAccount(ctx, authdb.CreateAccountParams{
			UserID:     user.ID,
			ProviderID: credentialProvider,
			AccountID:  user.Email,
			Password:   pgtype.Text{String: hashed, Valid: true},
		}); err != nil {
			slog.Error("failed to create account", "error", err)
			return c.String(http.StatusInternalServerError, "failed to create user")
		}

		if a.cfg.OnSignup != nil {
			if err := a.cfg.OnSignup(ctx, tx, user.ID); err != nil {
				slog.Error("OnSignup failed", "error", err, "user_id", user.ID)
				return c.String(http.StatusInternalServerError, "failed to create user")
			}
		}

		if err := tx.Commit(ctx); err != nil {
			slog.Error("failed to commit transaction", "error", err)
			return c.String(http.StatusInternalServerError, "failed to create user")
		}

		return c.JSON(http.StatusCreated, user)
	}
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Login answers the same 401 for an unknown email and a wrong password, so it
// cannot be used to find out which addresses are registered.
func (a *Auth) Login() echo.HandlerFunc {
	return func(c *echo.Context) error {
		var req LoginRequest
		if err := c.Bind(&req); err != nil {
			return c.String(http.StatusBadRequest, "invalid request body")
		}

		if req.Email == "" || req.Password == "" {
			return c.String(http.StatusBadRequest, "email and password are required")
		}

		ctx := c.Request().Context()

		account, err := a.q.GetAccountByEmail(ctx, authdb.GetAccountByEmailParams{
			AccountID:  req.Email,
			ProviderID: credentialProvider,
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return c.String(http.StatusUnauthorized, "invalid email or password")
			}
			slog.Error("failed to fetch account", "error", err)
			return c.String(http.StatusInternalServerError, "failed to log in")
		}

		if err := CheckPassword(req.Password, account.Password.String); err != nil {
			return c.String(http.StatusUnauthorized, "invalid email or password")
		}

		user, err := a.q.GetUserByID(ctx, account.UserID)
		if err != nil {
			slog.Error("failed to fetch user", "error", err)
			return c.String(http.StatusInternalServerError, "failed to log in")
		}

		if _, err := a.createSession(c, user.ID); err != nil {
			slog.Error("failed to create session", "error", err)
			return c.String(http.StatusInternalServerError, "failed to log in")
		}

		return c.JSON(http.StatusOK, user)
	}
}

// Logout drops the session row and clears the cookie. A caller without a
// cookie is already logged out, which is a success, not an error.
func (a *Auth) Logout() echo.HandlerFunc {
	return func(c *echo.Context) error {
		cookie, err := c.Cookie(a.cfg.CookieName)
		if err == nil && cookie.Value != "" {
			if err := a.q.DeleteSession(c.Request().Context(), cookie.Value); err != nil {
				slog.Error("failed to delete session", "error", err)
				return c.String(http.StatusInternalServerError, "failed to log out")
			}
		}

		a.clearSessionCookie(c)

		return c.NoContent(http.StatusNoContent)
	}
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

// ChangePassword requires the current password as well as the session, so a
// stolen cookie alone cannot lock the owner out.
func (a *Auth) ChangePassword() echo.HandlerFunc {
	return func(c *echo.Context) error {
		userID, ok := UserIDFromContext(c)
		if !ok {
			return c.String(http.StatusUnauthorized, "authentication required")
		}

		var req ChangePasswordRequest
		if err := c.Bind(&req); err != nil {
			return c.String(http.StatusBadRequest, "invalid request body")
		}

		if req.CurrentPassword == "" || req.NewPassword == "" {
			return c.String(http.StatusBadRequest, "currentPassword and newPassword are required")
		}

		if len(req.NewPassword) < a.cfg.MinPassword {
			return c.String(http.StatusBadRequest,
				fmt.Sprintf("newPassword must be at least %d characters", a.cfg.MinPassword))
		}

		ctx := c.Request().Context()

		account, err := a.q.GetAccountByUserID(ctx, authdb.GetAccountByUserIDParams{
			UserID:     userID,
			ProviderID: credentialProvider,
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return c.String(http.StatusBadRequest, "password login is not enabled for this account")
			}
			slog.Error("failed to fetch account", "error", err)
			return c.String(http.StatusInternalServerError, "failed to change password")
		}

		if err := CheckPassword(req.CurrentPassword, account.Password.String); err != nil {
			return c.String(http.StatusUnauthorized, "current password is incorrect")
		}

		hashed, err := HashPassword(req.NewPassword)
		if err != nil {
			slog.Error("failed to hash password", "error", err)
			return c.String(http.StatusInternalServerError, "failed to change password")
		}

		if err := a.q.UpdateAccountPassword(ctx, authdb.UpdateAccountPasswordParams{
			Password:   pgtype.Text{String: hashed, Valid: true},
			UserID:     userID,
			ProviderID: credentialProvider,
		}); err != nil {
			slog.Error("failed to update password", "error", err)
			return c.String(http.StatusInternalServerError, "failed to change password")
		}

		return c.NoContent(http.StatusNoContent)
	}
}
```

Two deliberate changes from the original, both worth noting in the commit message: the original `Signup` did not check the password length at all (only `ChangePassword` did), and the original `ChangePassword` used a literal `8` and a literal `"credential"` in four places. Both are now `a.cfg.MinPassword` and `credentialProvider`.

- [ ] **Step 4: Run the tests**

```bash
cd ~/dev/go-auth && go test . -v
```

Expected: PASS. If `TestSignup_ShortPasswordIsBadRequest` fails with an unmet `ExpectBegin`, the length check ended up after `Begin` — move it above.

- [ ] **Step 5: Commit**

```bash
cd ~/dev/go-auth
git add handlers.go handlers_test.go
git commit -m "feat: signup, login, logout and change password

Signup now enforces Config.MinPassword, which the original checked only on
change, and runs Config.OnSignup inside the signup transaction."
```

---

### Task 7: The password reset flow

Ported from `password_reset.go`, with `FRONTEND_URL` replaced by `Config.ResetURL` and the hardcoded copy by `Config.ResetEmail`.

**Files:**
- Create: `reset.go`
- Test: `reset_test.go`
- Reference: `~/dev/untitled-raffle-platform/api/internal/auth/password_reset.go`

**Interfaces:**
- Consumes: `Auth`, `Sender` (Task 3); `generateToken`, `resetTokenIdentifier` (Task 2); `HashPassword` (Task 2).
- Produces: `(a *Auth) ForgotPassword() echo.HandlerFunc`, `(a *Auth) VerifyResetToken() echo.HandlerFunc`, `(a *Auth) ResetPassword() echo.HandlerFunc`, the request types `ForgotPasswordRequest{Email string}`, `VerifyResetTokenRequest{Token string}`, `ResetPasswordRequest{Token, NewPassword string}`, and the unexported `(a *Auth) lookupResetToken(ctx context.Context, token string) (authdb.Verification, bool, error)`.

- [ ] **Step 1: Write the failing tests**

Create `reset_test.go`. Port the existing cases from `~/dev/untitled-raffle-platform/api/internal/auth/password_reset_test.go` (556 lines — this is the largest port in the plan), adjusting construction and row helpers as in Task 6. The existing suite already has a fake `Sender`; keep it. Add these cases, which cover the new configuration:

```go
// recordingSender captures what would have been emailed.
type recordingSender struct {
	mu                          sync.Mutex
	sent                        bool
	to, subject, text, htmlBody string
}

func (s *recordingSender) Send(ctx context.Context, to, subject, plainText, html string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent, s.to, s.subject, s.text, s.htmlBody = true, to, subject, plainText, html
	return nil
}

func (s *recordingSender) wait(t *testing.T) {
	t.Helper()

	// Delivery is detached, so poll briefly rather than sleeping a fixed time.
	for i := 0; i < 100; i++ {
		s.mu.Lock()
		sent := s.sent
		s.mu.Unlock()
		if sent {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatal("the reset email was never sent")
}

func TestForgotPassword_UsesConfiguredResetURL(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	hashed, err := HashPassword("whatever")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}

	mock.ExpectQuery("SELECT (.+) FROM accounts").
		WithArgs("user@example.test", "credential").
		WillReturnRows(accountRow(7, hashed))
	mock.ExpectQuery("SELECT (.+) FROM users").
		WithArgs(int64(7)).
		WillReturnRows(userRow(7, "User", "user@example.test", "user"))
	mock.ExpectExec("DELETE FROM verifications").
		WithArgs("7").
		WillReturnResult(pgxmock.NewResult("DELETE", 0))
	mock.ExpectQuery("INSERT INTO verifications").
		WithArgs(pgxmock.AnyArg(), "7", pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "identifier", "value", "expires_at", "created_at", "updated_at",
		}).AddRow(
			int64(1), "password-reset:abc", "7",
			pgtype.Timestamptz{Time: time.Now().Add(time.Minute), Valid: true},
			pgtype.Timestamptz{}, pgtype.Timestamptz{},
		))

	sender := &recordingSender{}
	a := newAuth(t, mock, Config{
		Mailer:   sender,
		ResetURL: func(token string) string { return "https://app.example.test/nueva-clave?t=" + token },
	})

	_, rec := serve(t, a.ForgotPassword(), http.MethodPost, "/auth/forgot-password",
		`{"email":"user@example.test"}`)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}

	sender.wait(t)

	if sender.to != "user@example.test" {
		t.Fatalf("emailed the wrong address: %q", sender.to)
	}

	if !strings.Contains(sender.text, "https://app.example.test/nueva-clave?t=") {
		t.Fatalf("the email does not carry the configured link: %q", sender.text)
	}
}

func TestForgotPassword_UsesConfiguredEmailCopy(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	hashed, err := HashPassword("whatever")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}

	mock.ExpectQuery("SELECT (.+) FROM accounts").
		WithArgs("user@example.test", "credential").
		WillReturnRows(accountRow(7, hashed))
	mock.ExpectQuery("SELECT (.+) FROM users").
		WithArgs(int64(7)).
		WillReturnRows(userRow(7, "User", "user@example.test", "user"))
	mock.ExpectExec("DELETE FROM verifications").
		WithArgs("7").
		WillReturnResult(pgxmock.NewResult("DELETE", 0))
	mock.ExpectQuery("INSERT INTO verifications").
		WithArgs(pgxmock.AnyArg(), "7", pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "identifier", "value", "expires_at", "created_at", "updated_at",
		}).AddRow(
			int64(1), "password-reset:abc", "7",
			pgtype.Timestamptz{Time: time.Now().Add(time.Minute), Valid: true},
			pgtype.Timestamptz{}, pgtype.Timestamptz{},
		))

	sender := &recordingSender{}
	a := newAuth(t, mock, Config{
		Mailer: sender,
		ResetEmail: func(name, link string, expiry time.Duration) (string, string, string) {
			return "Recuperá tu contraseña", "Hola " + name + ": " + link, "<p>" + link + "</p>"
		},
	})

	_, rec := serve(t, a.ForgotPassword(), http.MethodPost, "/auth/forgot-password",
		`{"email":"user@example.test"}`)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}

	sender.wait(t)

	if sender.subject != "Recuperá tu contraseña" {
		t.Fatalf("expected the configured subject, got %q", sender.subject)
	}
}

// An unknown address must answer exactly like a known one, or the endpoint
// tells an attacker which emails are registered.
func TestForgotPassword_UnknownEmailAnswers204(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	mock.ExpectQuery("SELECT (.+) FROM accounts").
		WithArgs("nobody@example.test", "credential").
		WillReturnError(pgx.ErrNoRows)

	sender := &recordingSender{}
	a := newAuth(t, mock, Config{Mailer: sender})

	_, rec := serve(t, a.ForgotPassword(), http.MethodPost, "/auth/forgot-password",
		`{"email":"nobody@example.test"}`)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}

	if sender.sent {
		t.Fatal("an email was sent for an unknown address")
	}
}

// The token is single-use: the second redemption finds nothing to claim.
func TestResetPassword_TokenIsSingleUse(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	mock.ExpectQuery("SELECT (.+) FROM verifications").
		WithArgs(pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "identifier", "value", "expires_at", "created_at", "updated_at",
		}).AddRow(
			int64(1), "password-reset:abc", "7",
			pgtype.Timestamptz{Time: time.Now().Add(time.Minute), Valid: true},
			pgtype.Timestamptz{}, pgtype.Timestamptz{},
		))
	// The claim finds zero rows: somebody else redeemed it first.
	mock.ExpectExec("DELETE FROM verifications").
		WithArgs(pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("DELETE", 0))

	a := newAuth(t, mock, Config{})
	_, rec := serve(t, a.ResetPassword(), http.MethodPost, "/auth/reset-password",
		`{"token":"tok","newPassword":"newpassword"}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for an already-redeemed token, got %d", rec.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

```bash
cd ~/dev/go-auth && go test . -run 'TestForgotPassword|TestVerifyResetToken|TestResetPassword' -v
```

Expected: FAIL to build, `a.ForgotPassword undefined` and friends.

- [ ] **Step 3: Write the implementation**

Create `reset.go`. Port `password_reset.go` from the source, applying exactly these changes and no others:

1. `queries *models.Queries` parameters become the `a *Auth` receiver; `queries.X` becomes `a.q.X`; `models.` becomes `authdb.`.
2. `resetTokenDuration` becomes `a.cfg.ResetTokenTTL`.
3. `"credential"` becomes `credentialProvider`.
4. `len(req.NewPassword) < 8` becomes `len(req.NewPassword) < a.cfg.MinPassword`, with the message built by `fmt.Sprintf` as in Task 6.
5. `resetPasswordEmail(user.Name, token)` becomes:

```go
link := a.cfg.ResetURL(url.QueryEscape(token))
subject, text, html := a.cfg.ResetEmail(user.Name, link, a.cfg.ResetTokenTTL)
```

6. Guard the mailer, which the original could assume was present:

```go
if a.cfg.Mailer == nil {
    slog.Error("password reset requested but no Mailer is configured")
    return c.String(http.StatusInternalServerError, "failed to process request")
}
```

Place this check immediately after binding and validating the request, before the account lookup — a misconfigured deployment should not write reset rows it can never deliver.

7. `sendMailTimeout` stays a package constant at `30 * time.Second`.

Everything else — the 204 for unknown addresses, the detached goroutine with its own context, deleting previous tokens before minting a new one, claiming the token with the row count *before* updating the password, and deleting every session afterwards — is preserved verbatim, comments included.

- [ ] **Step 4: Run the tests**

```bash
cd ~/dev/go-auth && go test . -v
```

Expected: PASS, the whole suite.

- [ ] **Step 5: Commit**

```bash
cd ~/dev/go-auth
git add reset.go reset_test.go
git commit -m "feat: the password reset flow, with the link and copy configurable"
```

---

### Task 8: Mount, cmd/authschema and the README

The wiring that makes the module usable from outside, and the schema publisher the consumer needs.

**Files:**
- Modify: `mount.go` (the stub from Task 5)
- Create: `cmd/authschema/main.go`, `schema.go`, `README.md`
- Test: `mount_test.go`, `cmd/authschema/main_test.go`

**Interfaces:**
- Consumes: every handler from Tasks 6-7.
- Produces: `(a *Auth) Mount(e *echo.Echo, prefix string)` registering six routes, and `Schema() string` returning the embedded DDL.

- [ ] **Step 1: Write the failing tests**

Create `mount_test.go`:

```go
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

	routes := map[string]bool{}
	for _, r := range e.Routes() {
		routes[r.Method()+" "+r.Path()] = true
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
```

Create `cmd/authschema/main_test.go`:

```go
package main

import (
	"strings"
	"testing"

	"github.com/sbstnrmrz/goauth"
)

// The published DDL must carry tern's marker, or the consumer's migration has
// no down half and tern refuses it.
func TestSchema_CarriesTernMarkerAndEveryTable(t *testing.T) {
	schema := goauth.Schema()

	if !strings.Contains(schema, "---- create above / drop below ----") {
		t.Fatal("the schema is missing tern's marker")
	}

	for _, table := range []string{"users", "accounts", "sessions", "verifications"} {
		if !strings.Contains(schema, "CREATE TABLE "+table) {
			t.Errorf("the schema does not create %s", table)
		}
	}

	if !strings.Contains(schema, "DO NOT EDIT") {
		t.Fatal("the schema is missing its generated-file header")
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

```bash
cd ~/dev/go-auth && go test ./... -run 'TestMount|TestSchema' -v
```

Expected: FAIL — `TestMount_RegistersEveryRoute` finds no routes, and `cmd/authschema` does not build (`undefined: goauth.Schema`).

- [ ] **Step 3: Write the implementation**

Replace `mount.go` with:

```go
package goauth

import "github.com/labstack/echo/v5"

// Mount creates a group at prefix, registers the authentication routes on it
// and records the prefix, which is what RequireAuth exempts. It takes the
// prefix rather than a ready-made *echo.Group because Echo v5 does not expose
// a group's prefix: there is no (*echo.Group).Prefix(), and the field is
// unexported.
//
// A consumer that wires the handlers individually instead has no recorded
// prefix and must exempt its login routes through Config.Skipper.
func (a *Auth) Mount(e *echo.Echo, prefix string) {
	a.prefix = prefix

	g := e.Group(prefix)

	g.POST("/signup", a.Signup())
	g.POST("/login", a.Login())
	g.POST("/logout", a.Logout())
	g.POST("/forgot-password", a.ForgotPassword())
	g.POST("/reset-password", a.ResetPassword())
	g.POST("/reset-password/verify", a.VerifyResetToken())
}
```

Create `schema.go`:

```go
package goauth

import _ "embed"

//go:embed migrations/auth.sql
var schema string

// Schema returns the DDL this module owns, ready to be written into a
// consumer's tern migration chain. goauth never applies it: the consumer's
// migration tool does, so the auth tables and the tables that reference them
// stay in one ordered chain.
func Schema() string {
	return schema
}
```

Create `cmd/authschema/main.go`:

```go
// Command authschema prints the DDL goauth owns, for a consumer's migration
// chain:
//
//	go run github.com/sbstnrmrz/goauth/cmd/authschema > migrations/001_auth.sql
//
// Do not regenerate over a migration that has already been applied: tern will
// not re-run it, so the checked-in DDL would stop describing the live
// database. A schema change means regenerating AND writing the matching ALTER.
package main

import (
	"fmt"
	"os"

	"github.com/sbstnrmrz/goauth"
)

func main() {
	if _, err := fmt.Fprint(os.Stdout, goauth.Schema()); err != nil {
		fmt.Fprintln(os.Stderr, "authschema:", err)
		os.Exit(1)
	}
}
```

- [ ] **Step 4: Run the tests**

```bash
cd ~/dev/go-auth && go test ./... -v
```

Expected: PASS, everything.

- [ ] **Step 5: Verify the command actually runs**

```bash
cd ~/dev/go-auth && go run ./cmd/authschema | head -20
```

Expected: the header comment followed by `CREATE TABLE users`.

- [ ] **Step 6: Write the README**

Create `README.md`:

````markdown
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
````

- [ ] **Step 7: Run the full suite and vet**

```bash
cd ~/dev/go-auth && go vet ./... && go test ./... && gofmt -l .
```

Expected: `go vet` silent, tests PASS, `gofmt -l` prints nothing.

- [ ] **Step 8: Commit**

```bash
cd ~/dev/go-auth
git add mount.go schema.go cmd/ README.md mount_test.go
git commit -m "feat: Mount, the schema publisher and the README"
```

---

## Verification

Run from `~/dev/go-auth` after the last task:

```bash
go vet ./...
go test ./... -count=1
gofmt -l .
go run ./cmd/authschema | head -5
```

All four must be clean: vet silent, tests passing with no database running, `gofmt -l` printing nothing, and the schema command printing its header.

One thing this plan cannot verify, and which is deliberately out of scope: that a real consumer compiles against the module and that the published DDL applies cleanly under tern. That happens in the follow-up work of migrating `untitled-raffle-platform/api`, which has its own design and plan.
