package goauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v5"

	"github.com/sbstnrmrz/goauth/authdb"
)

// sendMailTimeout bounds the background delivery of a reset email.
const sendMailTimeout = 30 * time.Second

type ForgotPasswordRequest struct {
	Email string `json:"email"`
}

// ForgotPassword mints a single-use reset token and emails it. It answers 204
// whether or not the address belongs to an account: telling callers which
// emails are registered would turn this into an account enumeration oracle.
func (a *Auth) ForgotPassword() echo.HandlerFunc {
	return func(c *echo.Context) error {
		var req ForgotPasswordRequest
		if err := c.Bind(&req); err != nil {
			return c.String(http.StatusBadRequest, "invalid request body")
		}

		if req.Email == "" {
			return c.String(http.StatusBadRequest, "email is required")
		}

		if a.cfg.Mailer == nil {
			slog.Error("password reset requested but no Mailer is configured")
			return c.String(http.StatusInternalServerError, "failed to process request")
		}

		ctx := c.Request().Context()

		account, err := a.q.GetAccountByEmail(ctx, authdb.GetAccountByEmailParams{
			AccountID:  req.Email,
			ProviderID: credentialProvider,
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return c.NoContent(http.StatusNoContent)
			}
			slog.Error("failed to fetch account", "error", err)
			return c.String(http.StatusInternalServerError, "failed to process request")
		}

		user, err := a.q.GetUserByID(ctx, account.UserID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return c.NoContent(http.StatusNoContent)
			}
			slog.Error("failed to fetch user", "error", err)
			return c.String(http.StatusInternalServerError, "failed to process request")
		}

		token, err := generateToken()
		if err != nil {
			slog.Error("failed to generate reset token", "error", err)
			return c.String(http.StatusInternalServerError, "failed to process request")
		}

		userID := strconv.FormatInt(user.ID, 10)

		// Requesting a new link invalidates any earlier one.
		if err := a.q.DeleteUserResetTokens(ctx, userID); err != nil {
			slog.Error("failed to clear previous reset tokens", "error", err)
			return c.String(http.StatusInternalServerError, "failed to process request")
		}

		if _, err := a.q.CreateVerification(ctx, authdb.CreateVerificationParams{
			Identifier: resetTokenIdentifier(token),
			Value:      userID,
			ExpiresAt:  pgtype.Timestamptz{Time: time.Now().Add(a.cfg.ResetTokenTTL), Valid: true},
		}); err != nil {
			slog.Error("failed to store reset token", "error", err)
			return c.String(http.StatusInternalServerError, "failed to process request")
		}

		// Delivery runs detached: the response must not wait on SMTP, and the
		// request context is cancelled as soon as we reply.
		go func() {
			sendCtx, cancel := context.WithTimeout(context.Background(), sendMailTimeout)
			defer cancel()

			link := a.cfg.ResetURL(url.QueryEscape(token))
			subject, text, html := a.cfg.ResetEmail(user.Name, link, a.cfg.ResetTokenTTL)
			if err := a.cfg.Mailer.Send(sendCtx, user.Email, subject, text, html); err != nil {
				slog.Error("failed to send reset email", "error", err, "user_id", user.ID)
			}
		}()

		return c.NoContent(http.StatusNoContent)
	}
}

// lookupResetToken resolves a raw token to its stored row. A token that is
// unknown or past its expiry reports ok=false; expired rows are dropped on the
// way out. A non-nil error means the lookup itself failed.
func (a *Auth) lookupResetToken(ctx context.Context, token string) (authdb.Verification, bool, error) {
	identifier := resetTokenIdentifier(token)

	verification, err := a.q.GetVerificationByIdentifier(ctx, identifier)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return authdb.Verification{}, false, nil
		}
		return authdb.Verification{}, false, err
	}

	if verification.ExpiresAt.Time.Before(time.Now()) {
		if _, err := a.q.DeleteVerification(ctx, identifier); err != nil {
			slog.Error("failed to delete expired reset token", "error", err)
		}
		return authdb.Verification{}, false, nil
	}

	return verification, true, nil
}

type VerifyResetTokenRequest struct {
	Token string `json:"token"`
}

// VerifyResetToken reports whether a reset link is still usable without
// consuming it, so the frontend can reject a dead link on arrival instead of
// after the user has filled in a new password. The token is taken from the
// body rather than the query string to keep it out of request logs.
func (a *Auth) VerifyResetToken() echo.HandlerFunc {
	return func(c *echo.Context) error {
		var req VerifyResetTokenRequest
		if err := c.Bind(&req); err != nil {
			return c.String(http.StatusBadRequest, "invalid request body")
		}

		if req.Token == "" {
			return c.String(http.StatusBadRequest, "token is required")
		}

		_, ok, err := a.lookupResetToken(c.Request().Context(), req.Token)
		if err != nil {
			slog.Error("failed to fetch reset token", "error", err)
			return c.String(http.StatusInternalServerError, "failed to verify reset token")
		}
		if !ok {
			return c.String(http.StatusBadRequest, "invalid or expired reset token")
		}

		return c.NoContent(http.StatusNoContent)
	}
}

type ResetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"newPassword"`
}

// ResetPassword redeems a token from ForgotPassword and sets a new password.
// The emailed token stands in for both the session and the current password
// that ChangePassword requires.
func (a *Auth) ResetPassword() echo.HandlerFunc {
	return func(c *echo.Context) error {
		var req ResetPasswordRequest
		if err := c.Bind(&req); err != nil {
			return c.String(http.StatusBadRequest, "invalid request body")
		}

		if req.Token == "" || req.NewPassword == "" {
			return c.String(http.StatusBadRequest, "token and newPassword are required")
		}

		if len(req.NewPassword) < a.cfg.MinPassword {
			return c.String(http.StatusBadRequest,
				fmt.Sprintf("newPassword must be at least %d characters", a.cfg.MinPassword))
		}

		ctx := c.Request().Context()
		identifier := resetTokenIdentifier(req.Token)

		verification, ok, err := a.lookupResetToken(ctx, req.Token)
		if err != nil {
			slog.Error("failed to fetch reset token", "error", err)
			return c.String(http.StatusInternalServerError, "failed to reset password")
		}
		if !ok {
			return c.String(http.StatusBadRequest, "invalid or expired reset token")
		}

		userID, err := strconv.ParseInt(verification.Value, 10, 64)
		if err != nil {
			slog.Error("reset token has malformed user id", "error", err, "value", verification.Value)
			return c.String(http.StatusInternalServerError, "failed to reset password")
		}

		hashed, err := HashPassword(req.NewPassword)
		if err != nil {
			slog.Error("failed to hash password", "error", err)
			return c.String(http.StatusInternalServerError, "failed to reset password")
		}

		// Claim the token before touching the password. Deleting first means a
		// later failure leaves the token spent rather than reusable, and the
		// row count makes the claim atomic against concurrent redemptions.
		claimed, err := a.q.DeleteVerification(ctx, identifier)
		if err != nil {
			slog.Error("failed to consume reset token", "error", err)
			return c.String(http.StatusInternalServerError, "failed to reset password")
		}
		if claimed == 0 {
			return c.String(http.StatusBadRequest, "invalid or expired reset token")
		}

		if err := a.q.UpdateAccountPassword(ctx, authdb.UpdateAccountPasswordParams{
			Password:   pgtype.Text{String: hashed, Valid: true},
			UserID:     userID,
			ProviderID: credentialProvider,
		}); err != nil {
			slog.Error("failed to update password", "error", err)
			return c.String(http.StatusInternalServerError, "failed to reset password")
		}

		// A reset may be recovery from a compromise, so drop every existing
		// login rather than leaving an attacker's session alive.
		if err := a.q.DeleteSessionsByUserID(ctx, userID); err != nil {
			slog.Error("failed to clear sessions after reset", "error", err, "user_id", userID)
			return c.String(http.StatusInternalServerError, "failed to reset password")
		}

		return c.NoContent(http.StatusNoContent)
	}
}
