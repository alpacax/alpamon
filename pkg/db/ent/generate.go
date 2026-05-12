package ent

//go:generate go run -mod=mod entgo.io/ent/cmd/ent@v0.14.5 generate --feature sql/modifier --target . ../schema
//go:generate go run -mod=mod ../../../scripts/patch-ent-client.go
