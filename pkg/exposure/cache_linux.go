//go:build linux

package exposure

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"reflect"
	"slices"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const fullReadInterval = 24 * time.Hour

type sourceIdentity struct {
	dev, ino, nlink uint64
	size            int64
	mtime, ctime    unix.Timespec
	mode, uid       uint32
}

func identityOf(st unix.Stat_t, uid uint32) sourceIdentity {
	return sourceIdentity{uint64(st.Dev), st.Ino, uint64(st.Nlink), st.Size, st.Mtim, st.Ctim, st.Mode, uid}
}

type sourceDependency struct {
	path      string
	rule      ownerRule
	id        sourceIdentity
	absent    bool
	directory bool
	names     []string
	dirs      []pathStat
}

type sourceTrace struct {
	dependencies []sourceDependency
	failed       bool
	read         bool
}

type sourceCacheEntry struct {
	epoch        int64
	input        any
	value        any
	dependencies []sourceDependency
}

type sourceCache struct {
	mu      sync.Mutex
	entries map[string]sourceCacheEntry
}

func newSourceCache() *sourceCache {
	return &sourceCache{entries: map[string]sourceCacheEntry{}}
}

// Each collection carries its own epoch so an abandoned worker cannot publish
// an old read as the next day's full read. No lock is held during filesystem IO.
func cachedSource[T any](f *fsReader, key string, input any, read func(*fsReader) T, complete func(T) bool, clone func(T) T) T {
	if f.cache == nil {
		return read(f)
	}
	f.cache.mu.Lock()
	entry, found := f.cache.entries[key]
	f.cache.mu.Unlock()
	if found && entry.epoch == f.epoch && reflect.DeepEqual(entry.input, input) && f.unchanged(entry.dependencies) {
		return clone(entry.value.(T))
	}
	local := &fsReader{rootFD: f.rootFD, root: f.root, mapOwner: f.mapOwner, trace: &sourceTrace{}}
	local.noOpenat2.Store(f.noOpenat2.Load())
	value := read(local)
	if !local.trace.failed && local.trace.read && complete(value) && local.unchanged(local.trace.dependencies) {
		stored := sourceCacheEntry{epoch: f.epoch, input: input, value: clone(value), dependencies: local.trace.dependencies}
		f.cache.mu.Lock()
		// A late worker must not replace a newer epoch's entry.
		if previous, ok := f.cache.entries[key]; !ok || previous.epoch <= f.epoch {
			f.cache.entries[key] = stored
		}
		f.cache.mu.Unlock()
	} else {
		f.cache.mu.Lock()
		if previous, ok := f.cache.entries[key]; ok && previous.epoch <= f.epoch {
			delete(f.cache.entries, key)
		}
		f.cache.mu.Unlock()
	}
	return value
}

func immutable[T any](v T) T { return v }

// File envelopes are copied because report capping may edit them and their
// slices. Only already parsed, wire-safe metadata reaches this helper.
func cloneSourceFile[T any](v T) T {
	data, err := json.Marshal(v)
	if err != nil {
		panic("cannot copy parsed exposure source")
	}
	var out T
	if json.Unmarshal(data, &out) != nil {
		panic("cannot copy parsed exposure source")
	}
	return out
}

func (f *fsReader) rememberFile(p string, rule ownerRule, st unix.Stat_t, dirs []pathStat, l loaded) {
	if f.trace == nil {
		return
	}
	if !l.complete() {
		f.trace.failed = true
		return
	}
	f.trace.read = f.trace.read || l.status == statusRead
	f.trace.dependencies = append(f.trace.dependencies, sourceDependency{path: p, rule: rule, id: identityOf(st, f.mapOwner(p, st.Uid)), absent: l.status == statusAbsent, dirs: dirs})
}

func directoryNames(f *fsReader, fd int) ([]string, bool) {
	readable, err := f.openAt(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return nil, false
	}
	dir := os.NewFile(uintptr(readable), "")
	defer func() { _ = dir.Close() }()
	names, err := dir.Readdirnames(maxDirEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false
	}
	if len(names) > maxDirEntries {
		return nil, false
	}
	slices.Sort(names)
	return names, true
}

func (f *fsReader) rememberDirectory(p string, fd int, rule ownerRule) {
	if f.trace == nil {
		return
	}
	p = path.Dir(p)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil {
		f.trace.failed = true
		return
	}
	names, ok := directoryNames(f, fd)
	if !ok {
		f.trace.failed = true
		return
	}
	f.trace.dependencies = append(f.trace.dependencies, sourceDependency{path: p, rule: rule, id: identityOf(st, f.mapOwner(p, st.Uid)), directory: true, names: names})
}

func (f *fsReader) unchanged(dependencies []sourceDependency) bool {
	for _, dep := range dependencies {
		fd, name, dirs, l, ok := f.walkDirs(dep.path, dep.rule, dep.directory)
		if !ok {
			if dep.absent && l.status == statusAbsent {
				continue
			}
			return false
		}
		matches := func() bool {
			if fd != f.rootFD {
				defer func() { _ = unix.Close(fd) }()
			}
			var st unix.Stat_t
			if dep.directory {
				if dep.absent {
					return false
				}
				if unix.Fstat(fd, &st) != nil || identityOf(st, f.mapOwner(dep.path, st.Uid)) != dep.id {
					return false
				}
				names, ok := directoryNames(f, fd)
				return ok && slices.Equal(names, dep.names)
			}
			err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
			if dep.absent {
				return err == unix.ENOENT
			}
			return err == nil && slices.Equal(dirs, dep.dirs) && f.acceptsRegular(dep.path, dep.rule, &st, dirs) && identityOf(st, f.mapOwner(dep.path, st.Uid)) == dep.id
		}()
		if !matches {
			return false
		}
	}
	return true
}
