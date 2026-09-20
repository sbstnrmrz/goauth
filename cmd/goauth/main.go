// Command goauth is the module's command-line tool.
//
//	goauth generate -o migrations/001_auth.sql
//
// Installed with:
//
//	go install github.com/sbstnrmrz/goauth/cmd/goauth@latest
//
// or run without installing:
//
//	go run github.com/sbstnrmrz/goauth/cmd/goauth generate -o migrations/001_auth.sql
//
// generate publishes the DDL goauth owns, for a consumer's migration chain.
// With -o it writes the file, creating the directory if it does not exist;
// without -o it prints to stdout, so the output can still be piped.
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
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/sbstnrmrz/goauth"
)

// usage is written to stderr for an unknown or missing subcommand. It lists
// every subcommand, because a tool with one subcommand today is exactly the
// tool someone will run with the wrong word tomorrow.
const usage = `goauth is the command-line tool for github.com/sbstnrmrz/goauth.

Usage:

	goauth <command> [flags]

Commands:

	generate    write the DDL goauth owns, for your migration chain

Run "goauth <command> -h" for a command's flags.
`

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "goauth:", err)
		os.Exit(1)
	}
}

// run dispatches a subcommand. It takes the arguments and the output stream
// rather than reading os.Args and writing os.Stdout directly, so the dispatch
// is testable without running a binary.
func run(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return errors.New("no command given")
	}

	switch args[0] {
	case "generate":
		return generate(args[1:], stdout)
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func generate(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("generate", flag.ContinueOnError)
	out := flags.String("o", "", "write the schema to this path instead of stdout, creating its directory")
	force := flags.Bool("f", false, "with -o, overwrite the file if it already exists")

	if err := flags.Parse(args); err != nil {
		return err
	}

	if *out == "" {
		_, err := fmt.Fprint(stdout, goauth.Schema())
		return err
	}

	return writeSchema(*out, *force)
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
