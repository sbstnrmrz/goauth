// Command authschema publishes the DDL goauth owns, for a consumer's migration
// chain:
//
//	go run github.com/sbstnrmrz/goauth/cmd/authschema -o migrations/001_auth.sql
//
// With -o it writes the file, creating the directory if it does not exist.
// Without -o it prints to stdout, so the output can still be piped.
//
// Do not regenerate over a migration that has already been applied: tern will
// not re-run it, so the checked-in DDL would stop describing the live
// database. A schema change means regenerating AND writing the matching ALTER.
// That is why -o refuses an existing file instead of overwriting it; -f is the
// way through once the overwrite is known to be safe.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/sbstnrmrz/goauth"
)

func main() {
	out := flag.String("o", "", "write the schema to this path instead of stdout, creating its directory")
	force := flag.Bool("f", false, "with -o, overwrite the file if it already exists")
	flag.Parse()

	if err := run(*out, *force); err != nil {
		fmt.Fprintln(os.Stderr, "authschema:", err)
		os.Exit(1)
	}
}

func run(out string, force bool) error {
	if out == "" {
		_, err := fmt.Fprint(os.Stdout, goauth.Schema())
		return err
	}

	return writeSchema(out, force)
}

// writeSchema writes the DDL to path, creating the parent directory. It refuses
// an existing file unless force is set: the likeliest file at a migration path
// is one already applied to a database, and silently rewriting it would leave
// the checked-in DDL describing something the database never ran.
func writeSchema(path string, force bool) error {
	if !force {
		switch _, err := os.Stat(path); {
		case err == nil:
			return fmt.Errorf("%s already exists; if it has been applied, write an ALTER migration instead, or pass -f to overwrite", path)
		case !errors.Is(err, fs.ErrNotExist):
			return err
		}
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	return os.WriteFile(path, []byte(goauth.Schema()), 0o644)
}
