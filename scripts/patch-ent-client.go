//go:build ignore

// patch-ent-client removes the migrate package reference from the generated
// pkg/db/ent/client.go. This eliminates the ariga.io/atlas postgres/mysql
// dialect dependency chain (~4.4MB), which is unused because alpamon migrates
// via raw SQL, not client.Schema.Create().
//
// Run via go:generate from pkg/db/ent/generate.go after ent code generation.
// Working directory when invoked is pkg/db/ent/, so "client.go" is resolved there.
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func main() {
	const path = "client.go"

	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "patch-ent-client: %v\n", err)
		os.Exit(1)
	}

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	f.Close()

	// Exact lines to remove from the generated client.go.
	drop := map[string]bool{
		`	"github.com/alpacax/alpamon/pkg/db/ent/migrate"`:              true,
		`	// Schema is the client for creating, migrating and dropping schema.`: true,
		`	Schema *migrate.Schema`:                                        true,
		`	c.Schema = migrate.NewSchema(c.driver)`:                        true,
	}

	removed := 0
	var out []string
	for _, line := range lines {
		if drop[line] {
			removed++
		} else {
			out = append(out, line)
		}
	}

	if removed == 0 {
		fmt.Printf("patch-ent-client: no migrate references found in %s — already clean\n", path)
		return
	}
	if removed != len(drop) {
		fmt.Fprintf(os.Stderr, "patch-ent-client: expected to remove %d lines, removed %d — client.go may have changed\n", len(drop), removed)
		os.Exit(1)
	}

	if err := os.WriteFile(path, []byte(strings.Join(out, "\n")+"\n"), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "patch-ent-client: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("patch-ent-client: removed %d migrate references from %s\n", removed, path)
}
