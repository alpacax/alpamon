package exposure

import "time"

// loaded is the outcome of reading one source through the secure reader.
// data is set only when status is read and the content is usable: a file
// that hit a cap or changed during the read comes back with no data.
type loaded struct {
	status  string
	reasons reasonSet
	data    []byte
	mtime   time.Time
	uid     uint32
	mode    uint32
}

func (l loaded) usable() bool { return l.status == statusRead && l.data != nil }

// complete reports whether the source was enumerated in full or verified
// absent, before any parse errors are counted.
func (l loaded) complete() bool {
	return l.status == statusAbsent || (l.status == statusRead && len(l.reasons) == 0)
}

func (l loaded) envelope(path string) envelope {
	r := reasonSet{}
	r.merge(l.reasons)
	return envelope{Path: path, Status: l.status, Complete: l.complete(), Reasons: r.list()}
}

// systemSource reads root-owned system files and directories. The Linux
// collector implements it on the secure reader; parser tests use a map.
type systemSource interface {
	// load reads a root-owned regular file.
	load(path string) loaded
	// list returns the entry names of a root-owned directory.
	list(path string) ([]string, loaded)
}

// includeWalker shares the traversal bounds and active include stack.
type includeWalker struct {
	src   systemSource
	stack map[string]bool
	files int
}

func (w *includeWalker) file(name string, depth int, visit func(loaded), fail func(string)) {
	if depth > maxIncludeDepth || w.files >= maxIncludeFiles {
		fail(reasonLimitExceeded)
		return
	}
	if w.stack[name] {
		fail(reasonParseError)
		return
	}
	if w.stack == nil {
		w.stack = map[string]bool{}
	}
	w.files++
	w.stack[name] = true
	defer delete(w.stack, name)
	visit(w.src.load(name))
}
