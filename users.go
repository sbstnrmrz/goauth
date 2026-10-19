package goauth

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/sbstnrmrz/goauth/authdb"
)

var (
	// ErrIdentifierTaken means the email or username is already registered.
	ErrIdentifierTaken = errors.New("goauth: email or username is already in use")

	// ErrPasswordTooShort means the password is under Config.MinPassword.
	ErrPasswordTooShort = errors.New("goauth: password is too short")

	// ErrIdentifierRequired means the identifier Config.LoginField signs in
	// with was left empty.
	ErrIdentifierRequired = errors.New("goauth: the login identifier is required")
)

// CreateUserParams describes a user and its credential account. Which of Email
// and Username is required follows Config.LoginField; the other is optional.
type CreateUserParams struct {
	// Name defaults to the username when it is empty and the login field is
	// username, since users.name is NOT NULL.
	Name     string
	Email    string
	Username string
	Image    string
	Password string

	// Role defaults to "user". goauth does not decide who may hold a role:
	// the caller does.
	Role string
}

// CreateUser inserts a user and its credential account on tx. It is what
// Signup uses, exported for a consumer that creates accounts itself, such as an
// administrator adding users with Config.DisableSignup set. The caller owns the
// transaction, so it can add its own rows before committing.
func (a *Auth) CreateUser(ctx context.Context, tx pgx.Tx, p CreateUserParams) (authdb.User, error) {
	identifier := p.Email
	if a.cfg.LoginField == LoginUsername {
		identifier = p.Username
	}

	if identifier == "" {
		return authdb.User{}, ErrIdentifierRequired
	}

	if len(p.Password) < a.cfg.MinPassword {
		return authdb.User{}, ErrPasswordTooShort
	}

	name := p.Name
	if name == "" {
		name = identifier
	}

	hashed, err := HashPassword(p.Password)
	if err != nil {
		return authdb.User{}, fmt.Errorf("goauth: hash password: %w", err)
	}

	qtx := authdb.New(tx)

	user, err := qtx.CreateUser(ctx, authdb.CreateUserParams{
		Name:     name,
		Email:    optionalText(p.Email),
		Username: optionalText(p.Username),
		Image:    optionalText(p.Image),
		Role:     p.Role,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return authdb.User{}, ErrIdentifierTaken
		}
		return authdb.User{}, fmt.Errorf("goauth: create user: %w", err)
	}

	if _, err := qtx.CreateAccount(ctx, authdb.CreateAccountParams{
		UserID:     user.ID,
		ProviderID: credentialProvider,
		AccountID:  identifier,
		Password:   pgtype.Text{String: hashed, Valid: true},
	}); err != nil {
		return authdb.User{}, fmt.Errorf("goauth: create account: %w", err)
	}

	return user, nil
}

// SetPassword replaces a user's password without asking for the old one, for an
// administrator resetting a lost password. Like a reset by email, it deletes
// every session of the user.
func (a *Auth) SetPassword(ctx context.Context, userID uuid.UUID, newPassword string) error {
	if len(newPassword) < a.cfg.MinPassword {
		return ErrPasswordTooShort
	}

	hashed, err := HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("goauth: hash password: %w", err)
	}

	tx, err := a.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("goauth: begin: %w", err)
	}
	defer tx.Rollback(ctx)

	qtx := authdb.New(tx)

	if err := qtx.UpdateAccountPassword(ctx, authdb.UpdateAccountPasswordParams{
		Password:   pgtype.Text{String: hashed, Valid: true},
		UserID:     userID,
		ProviderID: credentialProvider,
	}); err != nil {
		return fmt.Errorf("goauth: update password: %w", err)
	}

	if err := qtx.DeleteSessionsByUserID(ctx, userID); err != nil {
		return fmt.Errorf("goauth: delete sessions: %w", err)
	}

	return tx.Commit(ctx)
}

// SetDisabled blocks or restores a user's access. A disabled user cannot log in
// and RequireAuth rejects their sessions; disabling also deletes the sessions
// they already hold, and the user row stays so history keeps pointing at it.
func (a *Auth) SetDisabled(ctx context.Context, userID uuid.UUID, disabled bool) error {
	tx, err := a.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("goauth: begin: %w", err)
	}
	defer tx.Rollback(ctx)

	qtx := authdb.New(tx)

	if err := qtx.SetUserDisabled(ctx, authdb.SetUserDisabledParams{ID: userID, Disabled: disabled}); err != nil {
		return fmt.Errorf("goauth: set disabled: %w", err)
	}

	if disabled {
		if err := qtx.DeleteSessionsByUserID(ctx, userID); err != nil {
			return fmt.Errorf("goauth: delete sessions: %w", err)
		}
	}

	return tx.Commit(ctx)
}

func optionalText(s string) pgtype.Text {
	return pgtype.Text{String: s, Valid: s != ""}
}
