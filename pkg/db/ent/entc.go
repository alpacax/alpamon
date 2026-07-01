//go:build ignore

package main

import (
	"log"

	"entgo.io/ent/entc"
	"entgo.io/ent/entc/gen"
)

func main() {
	storage, err := gen.NewStorage("sql")
	if err != nil {
		log.Fatalf("ent codegen storage: %v", err)
	}
	// alpamon is SQLite-only and migrates via raw SQL in pkg/db/migration, never
	// client.Schema.Create(). Dropping Migrate skips the generated migrate package,
	// which is the sole entry point for the unused atlas postgres/mysql dialects.
	storage.SchemaMode &^= gen.Migrate

	if err := entc.Generate("../schema", &gen.Config{
		Target:   ".",
		Package:  "github.com/alpacax/alpamon/v2/pkg/db/ent",
		Storage:  storage,
		Features: []gen.Feature{gen.FeatureModifier}, // .Modify() used in collector batch queries
	}); err != nil {
		log.Fatalf("ent codegen generate: %v", err)
	}
}
