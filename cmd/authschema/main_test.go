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
