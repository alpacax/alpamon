package executor

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// killPrimitiveHomes maps each primitive that can find, open or kill processes by PID to the only
// functions allowed to name it. No home bans it from production code outright.
//
// Terminate only through a handle, a job object or a process group the command's cleanup created; never
// by PID or image name. A process snapshot is how a PID-based walk starts, OpenProcess and FindProcess
// turn a PID into a handle, and PROCESS_TERMINATE and PROCESS_ALL_ACCESS are the rights that make that
// handle a kill switch, so all of them stay out of every other function.
var killPrimitiveHomes = map[string][]string{
	"Process32First":           nil,
	"Process32Next":            nil,
	"FindProcess":              nil,
	"PROCESS_ALL_ACCESS":       nil,
	"CreateToolhelp32Snapshot": {"pkg/executor/process_tree_windows.go:resumeThreadsOfProcess"},
	"PROCESS_TERMINATE":        {"pkg/executor/process_tree_windows.go:commandCleanup.attachAndResume"},
	"TerminateProcess":         {"pkg/executor/process_tree_windows.go:commandCleanup.cancel"},
	"OpenProcess": {
		"pkg/executor/process_tree_windows.go:commandCleanup.attachAndResume",
		"pkg/pidfile/pidfile_windows.go:isProcess", // query-only liveness check
	},
}

// killCommandWords are kill paths spelled as text, which no identifier check sees: a command line run
// through a shell, or a procedure looked up by name. Matched case-insensitively in string literals.
var killCommandWords = []string{"taskkill", "stop-process", "terminateprocess", "ntterminateprocess"}

// Parses source rather than type-checking it, so files behind any build tag are covered on every
// runner: golangci-lint runs on Linux only and would never see a Windows file.
func TestKillPrimitivesStayInTheirHomes(t *testing.T) {
	root := filepath.Join("..", "..")
	seen := map[string]bool{} // "name@home" found where it is allowed
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
					switch n := n.(type) {
					case *ast.Ident:
						homes, banned := killPrimitiveHomes[n.Name]
						if !banned {
							return true
						}
						if slices.Contains(homes, where) {
							seen[n.Name+"@"+where] = true
							return true
						}
						assert.Fail(t, "kill primitive outside its home",
							"%s names %s at %s; only %q may (see killPrimitiveHomes)",
							where, n.Name, fset.Position(n.Pos()), homes)
					case *ast.BasicLit:
						if n.Kind != token.STRING {
							return true
						}
						lit := strings.ToLower(n.Value)
						for _, word := range killCommandWords {
							if strings.Contains(lit, word) {
								assert.Fail(t, "kill command in a string literal",
									"%s spells %q at %s (see killCommandWords)", where, word, fset.Position(n.Pos()))
							}
						}
					}
					return true
				})
			}
			return nil
		})
		require.NoError(t, err, "walk %s", dir)
	}

	// Proves the walk reached every home file: a guard that parsed nothing would pass silently.
	for name, homes := range killPrimitiveHomes {
		for _, home := range homes {
			assert.True(t, seen[name+"@"+home], "%s not found in its home %s; update killPrimitiveHomes", name, home)
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
