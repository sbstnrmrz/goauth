// Package goauth is email- or username-and-password authentication for Go services on
// PostgreSQL, built on pgx/v5 and Echo v5. It owns four tables: accounts,
// users, sessions and verifications.
//
// It never applies migrations. It publishes its DDL through cmd/goauth,
// a small program the consumer runs to fold that SQL into their own
// migration chain, so this module never needs to know how the consumer
// migrates.
//
// The pieces fit together as: New builds a configured *Auth; Mount registers
// the signup, login, logout and password-reset routes under a prefix and
// records that prefix; RequireAuth exempts that prefix and whatever
// Config.Skipper declares, and requires a valid session cookie for every
// other route it guards.
package goauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
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

// LoginField is the identifier a user signs in with.
type LoginField string

const (
	// LoginEmail signs in with the email address. It is the default.
	LoginEmail LoginField = "email"
	// LoginUsername signs in with users.username. The email stays optional.
	LoginUsername LoginField = "username"
)

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

	// LoginField picks what Signup and Login identify a user by. Defaults to
	// LoginEmail.
	LoginField LoginField

	// DisableSignup leaves POST /signup unmounted, for a deployment where users
	// are only created by an administrator through Auth.CreateUser.
	DisableSignup bool

	// DisableReset leaves the emailed password reset routes unmounted. A
	// consumer without them resets passwords itself through Auth.SetPassword.
	DisableReset bool

	// MinPassword is the shortest password accepted on signup, change and
	// reset. Defaults to 8.
	MinPassword int

	// Mailer delivers the password reset email. Required only if the reset
	// routes are mounted; ForgotPassword answers 500 without it.
	Mailer Sender

	// ResetURL builds the link emailed to a user, given a raw token. Required
	// unless DisableReset is set: only the consumer knows its front end. The
	// token is URL-escaped already.
	ResetURL func(token string) string

	// ResetEmail builds the reset message. Defaults to English copy; override
	// it for another language or to match a house style.
	ResetEmail func(name, link string, expiry time.Duration) (subject, text, html string)

	// Skipper exempts a request from RequireAuth. The module exempts its own
	// mounted prefix on its own; this is for the consumer's public routes.
	Skipper func(c *echo.Context) bool

	// Optional marks routes that work with or without a session, such as a
	// public page that also shows its owner their private records. A valid
	// session is loaded as on any other route; a missing, unknown or expired
	// one lets the request through anonymously instead of answering 401, so a
	// stale cookie never locks a visitor out of a public page. The mounted
	// prefix and Skipper take precedence: on those routes no session is read.
	Optional func(c *echo.Context) bool

	// OnSignup runs inside the transaction that creates the user and account,
	// before commit. A non-nil error rolls the whole signup back.
	OnSignup func(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error
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

	switch cfg.LoginField {
	case "":
		cfg.LoginField = LoginEmail
	case LoginEmail, LoginUsername:
	default:
		return nil, fmt.Errorf("goauth: unknown Config.LoginField %q", cfg.LoginField)
	}

	if cfg.ResetURL == nil && !cfg.DisableReset {
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
