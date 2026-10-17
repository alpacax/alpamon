// Package sqlitedsn builds the SQLite data source name pkg/db opens its database with. It sits under
// internal/ so pkg/db and its test helpers share one DSN without adding to pkg/'s public API.
package sqlitedsn

import "fmt"

// For returns the data source name for the database at path, with foreign keys enabled.
func For(path string) string {
	return fmt.Sprintf("file:%s?cache=shared&_pragma=foreign_keys(1)", path)
}
