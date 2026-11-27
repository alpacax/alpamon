//go:build linux

package exposure

import (
	"crypto/sha256"
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

const (
	fullReadInterval = 24 * time.Hour
	racyCleanWindow  = 2 * time.Second
)

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
	nameHash  [sha256.Size]byte
	dirs      []pathStat
	statTime  time.Time
}

type sourceTrace struct {
	dependencies []sourceDependency
	failed       bool
	recent       bool
	read         bool
}

type sourceCacheEntry struct {
	epoch        int64
	input        any
	value        any
	dependencies []sourceDependency
	touched      uint64
}

type sourceCache struct {
	mu         sync.Mutex
	entries    map[string]sourceCacheEntry
	collection uint64
	finished   bool
}

func newSourceCache() *sourceCache {
	return &sourceCache{entries: map[string]sourceCacheEntry{}}
}

func (c *sourceCache) beginCollection() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.collection++
	c.finished = false
	return c.collection
}

func (c *sourceCache) finishCollection(collection uint64, epoch int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.collection != collection {
		return
	}
	for key, entry := range c.entries {
		if entry.epoch < epoch || entry.touched != collection {
			delete(c.entries, key)
		}
	}
	c.finished = true
}

func (c *sourceCache) acceptsCollection(collection uint64) bool {
	return c.collection == collection && !c.finished
}

// Each collection carries its own epoch so an abandoned worker cannot publish
// an old read as the next day's full read. No lock is held during filesystem IO.
func cachedSource[T any](f *fsReader, key string, input any, read func(*fsReader) T, complete func(T) bool, clone func(T) T) T {
	return cachedSourceValidated(f, key, input, read, complete, clone, nil)
}

// invalidate prevents a caller from publishing a result whose dependencies
// changed during its own read, even when it has no persistent cache.
func cachedSourceValidated[T any](f *fsReader, key string, input any, read func(*fsReader) T, complete func(T) bool, clone func(T) T, invalidate func(T) T) T {
	if f.cache == nil && invalidate == nil {
		return read(f)
	}
	if f.cache != nil {
		f.cache.mu.Lock()
		entry, found := f.cache.entries[key]
		if !f.cache.acceptsCollection(f.collection) {
			found = false
		}
		if found {
			entry.touched = f.collection
			f.cache.entries[key] = entry
		}
		f.cache.mu.Unlock()
		if found && entry.epoch == f.epoch && reflect.DeepEqual(entry.input, input) && f.unchanged(entry.dependencies) {
			return clone(entry.value.(T))
		}
	}
	local := &fsReader{rootFD: f.rootFD, root: f.root, mapOwner: f.mapOwner, trace: &sourceTrace{}, now: f.now, cacheStat: f.cacheStat, scan: f.scan}
	local.noOpenat2.Store(f.noOpenat2.Load())
	value := read(local)
	stable := !local.trace.failed && local.trace.read && complete(value)
	if stable && (invalidate != nil || !local.trace.recent) {
		stable = local.unchanged(local.trace.dependencies)
	}
	if invalidate != nil && !stable {
		value = invalidate(value)
	}
	if f.cache == nil {
		return value
	}
	if stable && !local.trace.recent {
		stored := sourceCacheEntry{epoch: f.epoch, input: input, value: clone(value), dependencies: local.trace.dependencies, touched: f.collection}
		f.cache.mu.Lock()
		// A late worker must not replace a newer epoch's entry.
		if previous, ok := f.cache.entries[key]; f.cache.acceptsCollection(f.collection) && (!ok || previous.epoch <= f.epoch) {
			f.cache.entries[key] = stored
		}
		f.cache.mu.Unlock()
	} else {
		f.cache.mu.Lock()
		if previous, ok := f.cache.entries[key]; f.cache.acceptsCollection(f.collection) && ok && previous.epoch <= f.epoch {
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
	dep := sourceDependency{path: p, rule: rule, id: f.cacheIdentity(p, st), absent: l.status == statusAbsent, dirs: dirs, statTime: l.statTime}
	if !dep.absent && !timestampsOldEnough(dep.id, dep.statTime) {
		f.trace.recent = true
	}
	f.trace.dependencies = append(f.trace.dependencies, dep)
}

func directoryNames(f *fsReader, fd int) ([]string, bool) {
	if !f.scan.take() {
		return nil, false
	}
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

// Directory entries cannot contain NUL. Hash their sorted, delimited names
// so cache entries retain a fixed amount of metadata per directory.
func directoryDigest(names []string) [sha256.Size]byte {
	h := sha256.New()
	for _, name := range names {
		h.Write([]byte(name))
		h.Write([]byte{0})
	}
	var digest [sha256.Size]byte
	h.Sum(digest[:0])
	return digest
}

func (f *fsReader) rememberDirectory(p string, fd int, rule ownerRule) {
	if f.trace == nil {
		return
	}
	p = path.Dir(p)
	var st unix.Stat_t
	statTime := f.now()
	if unix.Fstat(fd, &st) != nil {
		f.trace.failed = true
		return
	}
	names, ok := directoryNames(f, fd)
	if !ok {
		f.trace.failed = true
		return
	}
	dep := sourceDependency{path: p, rule: rule, id: f.cacheIdentity(p, st), directory: true, nameHash: directoryDigest(names), statTime: statTime}
	if !timestampsOldEnough(dep.id, dep.statTime) {
		f.trace.recent = true
	}
	f.trace.dependencies = append(f.trace.dependencies, dep)
}

func (f *fsReader) unchanged(dependencies []sourceDependency) bool {
	for _, dep := range dependencies {
		if f.scan != nil && f.scan.ctx.Err() != nil {
			return false
		}
		if !dep.absent && !f.validCacheTime(dep.id, dep.statTime) {
			return false
		}
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
			statTime := f.now()
			if dep.directory {
				if dep.absent {
					return false
				}
				if unix.Fstat(fd, &st) != nil {
					return false
				}
				id := f.cacheIdentity(dep.path, st)
				if id != dep.id || !f.validCacheTime(id, statTime) {
					return false
				}
				names, ok := directoryNames(f, fd)
				return ok && directoryDigest(names) == dep.nameHash
			}
			err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
			if dep.absent {
				return err == unix.ENOENT
			}
			if err != nil {
				return false
			}
			id := f.cacheIdentity(dep.path, st)
			return slices.Equal(dirs, dep.dirs) && f.acceptsRegular(dep.path, dep.rule, &st, dirs) && id == dep.id && f.validCacheTime(id, statTime)
		}()
		if !matches {
			return false
		}
	}
	return true
}

func (f *fsReader) cacheIdentity(p string, st unix.Stat_t) sourceIdentity {
	if f.cacheStat != nil {
		f.cacheStat(p, &st)
	}
	return identityOf(st, f.mapOwner(p, st.Uid))
}

// A fresh read can confirm identity even when its timestamps are too recent
// to reuse the result in a later collection. A cache hit requires both.
func (f *fsReader) validCacheTime(id sourceIdentity, at time.Time) bool {
	if timestampsOldEnough(id, at) {
		return true
	}
	if f.trace == nil {
		return false
	}
	f.trace.recent = true
	return true
}

func timestampsOldEnough(id sourceIdentity, statTime time.Time) bool {
	cutoff := statTime.Add(-racyCleanWindow)
	return time.Unix(id.mtime.Sec, id.mtime.Nsec).Before(cutoff) &&
		time.Unix(id.ctime.Sec, id.ctime.Nsec).Before(cutoff)
}
