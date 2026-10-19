package authdb

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
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
			"user_agent", "created_at", "updated_at", "role", "disabled_at",
		}).AddRow(
			uuid.UUID{15: 1}, "tok", uuid.UUID{15: 7},
			pgtype.Timestamptz{Time: expiresAt, Valid: true},
			pgtype.Text{}, pgtype.Text{},
			pgtype.Timestamptz{}, pgtype.Timestamptz{}, "admin",
			pgtype.Timestamptz{},
		))

	row, err := New(mock).GetSessionByToken(context.Background(), "tok")
	if err != nil {
		t.Fatalf("GetSessionByToken returned error: %v", err)
	}

	if row.Session.UserID != (uuid.UUID{15: 7}) {
		t.Fatalf("expected user id 7, got %s", row.Session.UserID)
	}

	if row.Role != "admin" {
		t.Fatalf("expected role %q, got %q", "admin", row.Role)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
