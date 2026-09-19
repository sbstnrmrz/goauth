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
