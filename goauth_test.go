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
