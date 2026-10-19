package goauth

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5"
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
	Username string `json:"username"`
	Password string `json:"password"`
	Image    string `json:"image"`
}

// Signup creates a user and its credential account in one transaction, then
// runs Config.OnSignup inside that same transaction so a consumer can add its
// own rows. It deliberately does not sign the new user in, and it never accepts
// a role: new users get the default one.
func (a *Auth) Signup() echo.HandlerFunc {
	return func(c *echo.Context) error {
		var req SignupRequest
		if err := c.Bind(&req); err != nil {
			return c.String(http.StatusBadRequest, "invalid request body")
		}

		if a.cfg.LoginField == LoginUsername {
			if req.Username == "" || req.Password == "" {
				return c.String(http.StatusBadRequest, "username and password are required")
			}
		} else if req.Name == "" || req.Email == "" || req.Password == "" {
			return c.String(http.StatusBadRequest, "name, email and password are required")
		}

		// Validate before opening the transaction, so a doomed request never
		// needs a rollback.
		if len(req.Password) < a.cfg.MinPassword {
			return c.String(http.StatusBadRequest,
				fmt.Sprintf("password must be at least %d characters", a.cfg.MinPassword))
		}

		ctx := c.Request().Context()

		tx, err := a.db.Begin(ctx)
		if err != nil {
			slog.Error("failed to begin transaction", "error", err)
			return c.String(http.StatusInternalServerError, "failed to create user")
		}
		defer tx.Rollback(ctx)

		user, err := a.CreateUser(ctx, tx, CreateUserParams{
			Name:     req.Name,
			Email:    req.Email,
			Username: req.Username,
			Image:    req.Image,
			Password: req.Password,
		})
		if err != nil {
			if errors.Is(err, ErrIdentifierTaken) {
				return c.String(http.StatusConflict, string(a.cfg.LoginField)+" is already in use")
			}
			slog.Error("failed to create user", "error", err)
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
	Username string `json:"username"`
	Password string `json:"password"`
}

// Login answers the same 401 for an unknown identifier and a wrong password,
// so it cannot be used to find out which accounts exist. The identifier is the
// email or the username, per Config.LoginField.
func (a *Auth) Login() echo.HandlerFunc {
	return func(c *echo.Context) error {
		var req LoginRequest
		if err := c.Bind(&req); err != nil {
			return c.String(http.StatusBadRequest, "invalid request body")
		}

		identifier := req.Email
		if a.cfg.LoginField == LoginUsername {
			identifier = req.Username
		}

		if identifier == "" || req.Password == "" {
			return c.String(http.StatusBadRequest,
				string(a.cfg.LoginField)+" and password are required")
		}

		ctx := c.Request().Context()

		var (
			account authdb.Account
			err     error
		)
		if a.cfg.LoginField == LoginUsername {
			account, err = a.q.GetAccountByUsername(ctx, authdb.GetAccountByUsernameParams{
				Username:   pgtype.Text{String: identifier, Valid: true},
				ProviderID: credentialProvider,
			})
		} else {
			account, err = a.q.GetAccountByEmail(ctx, authdb.GetAccountByEmailParams{
				AccountID:  identifier,
				ProviderID: credentialProvider,
			})
		}
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return c.String(http.StatusUnauthorized, "invalid "+string(a.cfg.LoginField)+" or password")
			}
			slog.Error("failed to fetch account", "error", err)
			return c.String(http.StatusInternalServerError, "failed to log in")
		}

		if err := CheckPassword(req.Password, account.Password.String); err != nil {
			return c.String(http.StatusUnauthorized, "invalid "+string(a.cfg.LoginField)+" or password")
		}

		user, err := a.q.GetUserByID(ctx, account.UserID)
		if err != nil {
			slog.Error("failed to fetch user", "error", err)
			return c.String(http.StatusInternalServerError, "failed to log in")
		}

		// Checked after the password, so a disabled account is not revealed to
		// someone who does not know it.
		if user.DisabledAt.Valid {
			return c.String(http.StatusForbidden, "account disabled")
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
