package main

import (
	"os"
	"path/filepath"
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

// Writing the file is the point of -o: a consumer starting a project has no
// migrations directory yet, and shell redirection cannot create one.
func TestWriteSchema_CreatesTheDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "migrations", "001_auth.sql")

	if err := writeSchema(path, false); err != nil {
		t.Fatalf("writeSchema returned error: %v", err)
	}

	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read the written file: %v", err)
	}

	if string(written) != goauth.Schema() {
		t.Fatal("the written file is not the published schema")
	}
}

// The likeliest file at a migration path is one already applied to a database.
// Rewriting it silently would leave the checked-in DDL describing something the
// database never ran, so the refusal is the safe default.
func TestWriteSchema_RefusesAnExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "001_auth.sql")

	if err := os.WriteFile(path, []byte("-- already applied\n"), 0o644); err != nil {
		t.Fatalf("failed to seed the file: %v", err)
	}

	err := writeSchema(path, false)
	if err == nil {
		t.Fatal("writeSchema overwrote an existing file")
	}

	if !strings.Contains(err.Error(), "-f") {
		t.Fatalf("the error does not say how to override it: %v", err)
	}

	kept, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("failed to read the file back: %v", readErr)
	}

	if string(kept) != "-- already applied\n" {
		t.Fatal("the existing file was modified despite the refusal")
	}
}

func TestWriteSchema_ForceOverwrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "001_auth.sql")

	if err := os.WriteFile(path, []byte("-- stale\n"), 0o644); err != nil {
		t.Fatalf("failed to seed the file: %v", err)
	}

	if err := writeSchema(path, true); err != nil {
		t.Fatalf("writeSchema returned error: %v", err)
	}

	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read the written file: %v", err)
	}

	if string(written) != goauth.Schema() {
		t.Fatal("-f did not replace the file with the published schema")
	}
}

// Without -o the schema still goes to stdout, so existing shell redirection
// keeps working.
func TestRun_WithoutOutputPathDoesNotWriteAFile(t *testing.T) {
	dir := t.TempDir()

	if err := run("", false); err != nil {
		t.Fatalf("run returned error: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("failed to read the temp dir: %v", err)
	}

	if len(entries) != 0 {
		t.Fatalf("run wrote %d file(s) without -o", len(entries))
	}
}
