// Command authschema prints the DDL goauth owns, for a consumer's migration
// chain:
//
//	go run github.com/sbstnrmrz/goauth/cmd/authschema > migrations/001_auth.sql
//
// Do not regenerate over a migration that has already been applied: tern will
// not re-run it, so the checked-in DDL would stop describing the live
// database. A schema change means regenerating AND writing the matching ALTER.
package main

import (
	"fmt"
	"os"

	"github.com/sbstnrmrz/goauth"
)

func main() {
	if _, err := fmt.Fprint(os.Stdout, goauth.Schema()); err != nil {
		fmt.Fprintln(os.Stderr, "authschema:", err)
		os.Exit(1)
	}
}
