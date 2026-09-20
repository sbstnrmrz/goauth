package goauth

import _ "embed"

//go:embed schema/auth.sql
var schema string

// Schema returns the DDL this module owns, ready to be written into a
// consumer's tern migration chain. goauth never applies it: the consumer's
// migration tool does, so the auth tables and the tables that reference them
// stay in one ordered chain.
func Schema() string {
	return schema
}
