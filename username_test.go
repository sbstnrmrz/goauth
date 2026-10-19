package goauth

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v5"
	"github.com/pashagolub/pgxmock/v5"
)

func disabledUserRow(mock pgxmock.PgxPoolIface) *pgxmock.Rows {
	return pgxmock.NewRows([]string{
		"id", "name", "email", "username", "image", "role", "disabled_at",
		"created_at", "updated_at",
	}).AddRow(
		tid(7), "ana", pgtype.Text{}, pgtype.Text{String: "ana", Valid: true},
		pgtype.Text{}, "volunteer", pgtype.Timestamptz{Time: time.Now(), Valid: true},
		pgtype.Timestamptz{}, pgtype.Timestamptz{},
	)
}

func TestNew_RejectsUnknownLoginField(t *testing.T) {
	mock, _ := pgxmock.NewPool()
	defer mock.Close()

	if _, err := New(mock, Config{LoginField: "phone", DisableReset: true}); err == nil {
		t.Fatal("expected an error for an unknown LoginField")
	}
}

func TestNew_ResetURLNotRequiredWhenResetDisabled(t *testing.T) {
	mock, _ := pgxmock.NewPool()
	defer mock.Close()

	if _, err := New(mock, Config{DisableReset: true}); err != nil {
		t.Fatalf("New returned error: %v", err)
	}
}

func TestMount_DisabledRoutesAreNotRegistered(t *testing.T) {
	mock, _ := pgxmock.NewPool()
	defer mock.Close()

	e := echo.New()
	a := newAuth(t, mock, Config{DisableSignup: true, DisableReset: true})
	a.Mount(e, "/auth")

	routes := map[string]bool{}
	for _, r := range e.Router().Routes() {
		routes[r.Method+" "+r.Path] = true
	}

	for _, gone := range []string{
		"POST /auth/signup",
		"POST /auth/forgot-password",
		"POST /auth/reset-password",
		"POST /auth/reset-password/verify",
	} {
		if routes[gone] {
			t.Errorf("route should not be registered: %s", gone)
		}
	}

	for _, kept := range []string{"POST /auth/login", "POST /auth/logout"} {
		if !routes[kept] {
			t.Errorf("route not registered: %s", kept)
		}
	}
}

func TestLogin_UsernameSuccess(t *testing.T) {
	mock, _ := pgxmock.NewPool()
	defer mock.Close()

	hashed, err := HashPassword("right-password")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}

	mock.ExpectQuery("SELECT (.+) FROM accounts").
		WithArgs(pgtype.Text{String: "ana", Valid: true}, "credential").
		WillReturnRows(accountRow(tid(7), hashed))
	mock.ExpectQuery("SELECT (.+) FROM users").
		WithArgs(tid(7)).
		WillReturnRows(userRow(tid(7), "ana", "", "volunteer"))
	mock.ExpectQuery("INSERT INTO sessions").
		WithArgs(pgxmock.AnyArg(), tid(7), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "token", "user_id", "expires_at", "ip_address",
			"user_agent", "created_at", "updated_at",
		}).AddRow(
			tid(1), "stored", tid(7),
			pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true},
			pgtype.Text{}, pgtype.Text{},
			pgtype.Timestamptz{}, pgtype.Timestamptz{},
		))

	a := newAuth(t, mock, Config{LoginField: LoginUsername})
	_, rec := serve(t, a.Login(), http.MethodPost, "/auth/login",
		`{"username":"ana","password":"right-password"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// In username mode an email in the body is not an identifier.
func TestLogin_UsernameModeRequiresUsername(t *testing.T) {
	mock, _ := pgxmock.NewPool()
	defer mock.Close()

	a := newAuth(t, mock, Config{LoginField: LoginUsername})
	_, rec := serve(t, a.Login(), http.MethodPost, "/auth/login",
		`{"email":"ana@example.test","password":"whatever"}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestLogin_DisabledUserIsForbidden(t *testing.T) {
	mock, _ := pgxmock.NewPool()
	defer mock.Close()

	hashed, _ := HashPassword("right-password")

	mock.ExpectQuery("SELECT (.+) FROM accounts").
		WithArgs(pgtype.Text{String: "ana", Valid: true}, "credential").
		WillReturnRows(accountRow(tid(7), hashed))
	mock.ExpectQuery("SELECT (.+) FROM users").
		WithArgs(tid(7)).
		WillReturnRows(disabledUserRow(mock))

	a := newAuth(t, mock, Config{LoginField: LoginUsername})
	_, rec := serve(t, a.Login(), http.MethodPost, "/auth/login",
		`{"username":"ana","password":"right-password"}`)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}

	if len(rec.Result().Cookies()) != 0 {
		t.Fatal("a disabled user must not receive a session cookie")
	}
}

// A wrong password must not reveal that the account is disabled.
func TestLogin_DisabledUserWrongPasswordIsUnauthorized(t *testing.T) {
	mock, _ := pgxmock.NewPool()
	defer mock.Close()

	hashed, _ := HashPassword("right-password")

	mock.ExpectQuery("SELECT (.+) FROM accounts").
		WithArgs(pgtype.Text{String: "ana", Valid: true}, "credential").
		WillReturnRows(accountRow(tid(7), hashed))

	a := newAuth(t, mock, Config{LoginField: LoginUsername})
	_, rec := serve(t, a.Login(), http.MethodPost, "/auth/login",
		`{"username":"ana","password":"wrong-password"}`)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestRequireAuth_RejectsDisabledUser(t *testing.T) {
	mock, _ := pgxmock.NewPool()
	defer mock.Close()

	mock.ExpectQuery("SELECT sessions.id").
		WithArgs("tok").
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "token", "user_id", "expires_at", "ip_address",
			"user_agent", "created_at", "updated_at", "role", "disabled_at",
		}).AddRow(
			tid(1), "tok", tid(7),
			pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true},
			pgtype.Text{}, pgtype.Text{},
			pgtype.Timestamptz{}, pgtype.Timestamptz{}, "volunteer",
			pgtype.Timestamptz{Time: time.Now(), Valid: true},
		))

	a := newAuth(t, mock, Config{})
	c, rec := requestContext(t, "session_token", "tok")

	called := false
	handler := a.RequireAuth()(func(c *echo.Context) error {
		called = true
		return c.NoContent(http.StatusOK)
	})

	if err := handler(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if called || rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without reaching the handler, got %d (called=%v)", rec.Code, called)
	}
}

func TestSignup_UsernameMode(t *testing.T) {
	mock, _ := pgxmock.NewPool()
	defer mock.Close()

	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO users").
		WithArgs("ana", pgtype.Text{}, pgtype.Text{String: "ana", Valid: true}, pgtype.Text{}, "").
		WillReturnRows(userRow(tid(7), "ana", "", "user"))
	mock.ExpectQuery("INSERT INTO accounts").
		WithArgs(tid(7), "credential", "ana", pgxmock.AnyArg()).
		WillReturnRows(accountRow(tid(7), "hashed"))
	mock.ExpectCommit()
	mock.ExpectRollback()

	a := newAuth(t, mock, Config{LoginField: LoginUsername})
	_, rec := serve(t, a.Signup(), http.MethodPost, "/auth/signup",
		`{"username":"ana","password":"password1"}`)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d (%s)", rec.Code, rec.Body.String())
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestCreateUser_SetsRoleAndReportsDuplicates(t *testing.T) {
	mock, _ := pgxmock.NewPool()
	defer mock.Close()

	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO users").
		WithArgs("ana", pgtype.Text{}, pgtype.Text{String: "ana", Valid: true}, pgtype.Text{}, "volunteer").
		WillReturnRows(userRow(tid(7), "ana", "", "volunteer"))
	mock.ExpectQuery("INSERT INTO accounts").
		WithArgs(tid(7), "credential", "ana", pgxmock.AnyArg()).
		WillReturnRows(accountRow(tid(7), "hashed"))
	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO users").
		WithArgs("ana", pgtype.Text{}, pgtype.Text{String: "ana", Valid: true}, pgtype.Text{}, "volunteer").
		WillReturnError(&pgconn.PgError{Code: "23505"})

	a := newAuth(t, mock, Config{LoginField: LoginUsername})
	ctx := context.Background()
	p := CreateUserParams{Username: "ana", Password: "password1", Role: "volunteer"}

	tx, _ := mock.Begin(ctx)
	user, err := a.CreateUser(ctx, tx, p)
	if err != nil {
		t.Fatalf("CreateUser returned error: %v", err)
	}
	if user.Role != "volunteer" {
		t.Fatalf("expected role volunteer, got %q", user.Role)
	}

	tx, _ = mock.Begin(ctx)
	if _, err := a.CreateUser(ctx, tx, p); !errors.Is(err, ErrIdentifierTaken) {
		t.Fatalf("expected ErrIdentifierTaken, got %v", err)
	}
}

func TestCreateUser_Validation(t *testing.T) {
	mock, _ := pgxmock.NewPool()
	defer mock.Close()

	a := newAuth(t, mock, Config{LoginField: LoginUsername})
	ctx := context.Background()

	if _, err := a.CreateUser(ctx, nil, CreateUserParams{Password: "password1"}); !errors.Is(err, ErrIdentifierRequired) {
		t.Fatalf("expected ErrIdentifierRequired, got %v", err)
	}

	if _, err := a.CreateUser(ctx, nil, CreateUserParams{Username: "ana", Password: "short"}); !errors.Is(err, ErrPasswordTooShort) {
		t.Fatalf("expected ErrPasswordTooShort, got %v", err)
	}
}

func TestSetPassword_UpdatesAndDropsSessions(t *testing.T) {
	mock, _ := pgxmock.NewPool()
	defer mock.Close()

	mock.ExpectBegin()
	mock.ExpectExec("UPDATE accounts").
		WithArgs(pgxmock.AnyArg(), tid(7), "credential").
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	mock.ExpectExec("DELETE FROM sessions").
		WithArgs(tid(7)).
		WillReturnResult(pgxmock.NewResult("DELETE", 2))
	mock.ExpectCommit()
	mock.ExpectRollback()

	a := newAuth(t, mock, Config{})
	if err := a.SetPassword(context.Background(), tid(7), "new-password"); err != nil {
		t.Fatalf("SetPassword returned error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestSetPassword_TooShort(t *testing.T) {
	mock, _ := pgxmock.NewPool()
	defer mock.Close()

	a := newAuth(t, mock, Config{})
	if err := a.SetPassword(context.Background(), tid(7), "short"); !errors.Is(err, ErrPasswordTooShort) {
		t.Fatalf("expected ErrPasswordTooShort, got %v", err)
	}
}

func TestSetDisabled_DisablingDropsSessions(t *testing.T) {
	mock, _ := pgxmock.NewPool()
	defer mock.Close()

	mock.ExpectBegin()
	mock.ExpectExec("UPDATE users").
		WithArgs(true, tid(7)).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	mock.ExpectExec("DELETE FROM sessions").
		WithArgs(tid(7)).
		WillReturnResult(pgxmock.NewResult("DELETE", 1))
	mock.ExpectCommit()
	mock.ExpectRollback()

	a := newAuth(t, mock, Config{})
	if err := a.SetDisabled(context.Background(), tid(7), true); err != nil {
		t.Fatalf("SetDisabled returned error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestSetDisabled_EnablingKeepsSessionsAlone(t *testing.T) {
	mock, _ := pgxmock.NewPool()
	defer mock.Close()

	mock.ExpectBegin()
	mock.ExpectExec("UPDATE users").
		WithArgs(false, tid(7)).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	mock.ExpectCommit()
	mock.ExpectRollback()

	a := newAuth(t, mock, Config{})
	if err := a.SetDisabled(context.Background(), tid(7), false); err != nil {
		t.Fatalf("SetDisabled returned error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
