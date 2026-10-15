package executor

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// killPrimitiveHomes maps each Windows primitive that can find or kill processes by PID to the one
// function allowed to name it. An empty home bans it from production code outright.
//
// Terminate only through a handle, a job object or a process group the command's cleanup created; never
// by PID or image name. A process snapshot is how a PID-based walk starts, and PROCESS_TERMINATE is the
// right that walk opens PIDs with, so both stay out of every other function.
var killPrimitiveHomes = map[string]string{
	"Process32First":           "",
	"Process32Next":            "",
	"CreateToolhelp32Snapshot": "pkg/executor/process_tree_windows.go:resumeThreadsOfProcess",
	"PROCESS_TERMINATE":        "pkg/executor/process_tree_windows.go:commandCleanup.attachAndResume",
	"TerminateProcess":         "pkg/executor/process_tree_windows.go:commandCleanup.cancel",
}

// Parses source rather than type-checking it, so files behind any build tag are covered on every
// runner: golangci-lint runs on Linux only and would never see a Windows file.
func TestKillPrimitivesStayInTheirHomes(t *testing.T) {
	root := filepath.Join("..", "..")
	seen := map[string]bool{}
	fset := token.NewFileSet()

	for _, dir := range []string{"cmd", "internal", "pkg"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			for _, decl := range file.Decls {
				where := rel + ":" + declName(decl)
				ast.Inspect(decl, func(n ast.Node) bool {
					id, ok := n.(*ast.Ident)
					if !ok {
						return true
					}
					home, banned := killPrimitiveHomes[id.Name]
					if !banned {
						return true
					}
					if where == home {
						seen[id.Name] = true
						return true
					}
					assert.Fail(t, "kill primitive outside its home",
						"%s names %s at %s; only %q may (see killPrimitiveHomes)",
						where, id.Name, fset.Position(id.Pos()), home)
					return true
				})
			}
			return nil
		})
		require.NoError(t, err, "walk %s", dir)
	}

	// Proves the walk reached the home file: a guard that parsed nothing would pass silently.
	for name, home := range killPrimitiveHomes {
		if home != "" {
			assert.True(t, seen[name], "%s not found in its home %s; update killPrimitiveHomes", name, home)
		}
	}
}

// declName names a top-level declaration as Type.method, func, or "" for package-level declarations.
func declName(decl ast.Decl) string {
	fn, ok := decl.(*ast.FuncDecl)
	if !ok {
		return ""
	}
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	typ := fn.Recv.List[0].Type
	if star, ok := typ.(*ast.StarExpr); ok {
		typ = star.X
	}
	if id, ok := typ.(*ast.Ident); ok {
		return id.Name + "." + fn.Name.Name
	}
	return fn.Name.Name
}
