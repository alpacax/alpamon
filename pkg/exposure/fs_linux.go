//go:build linux

package exposure

import (
	"errors"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// fsReader reads files under a pinned root directory. Only root-owned
// directory symlinks reached entirely through root-owned directories without
// group/world write permission are resolved; account paths use no-follow opens.
type fsReader struct {
	rootFD int
	root   unix.Stat_t
	// mapOwner turns a file's uid into the uid ownership is judged by. It is
	// the identity in production; tests, which run unprivileged, map their
	// own uid to root or to an account.
	mapOwner  func(path string, uid uint32) uint32
	noOpenat2 atomic.Bool
}

// Test hooks; nil outside tests.
var (
	// testHookOpen runs before each component is opened and may fail it.
	testHookOpen func(path string) error
	// testHookFstat may rewrite the fstat result of a final component.
	testHookFstat func(path string, st *unix.Stat_t)
	// testHookRead runs before a file's content is read; it may block.
	testHookRead func(path string)
	// testHookAfterRead runs between the read and the second fstat.
	testHookAfterRead func(path string)
	// testForceNoOpenat2 makes new readers use the O_NOFOLLOW fallback.
	testForceNoOpenat2 bool
)

func newFSReader(root string, mapOwner func(string, uint32) uint32) (*fsReader, error) {
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := &fsReader{rootFD: fd, mapOwner: mapOwner}
	if err := unix.Fstat(fd, &f.root); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if testForceNoOpenat2 {
		f.noOpenat2.Store(true)
	}
	return f, nil
}

func (f *fsReader) close() { _ = unix.Close(f.rootFD) }

// ownerRule says who may own what is read: system sources must be owned by
// root, account sources by root or the account, with a single hard link.
type ownerRule struct {
	system bool
	uid    uint32
}

func (o ownerRule) allows(uid uint32) bool {
	return uid == 0 || (!o.system && uid == o.uid)
}

// pathStat is the ownership and mode of one walked component.
type pathStat struct {
	path string
	uid  uint32
	mode uint32
}

func retryEINTR(fn func() (int, error)) (int, error) {
	for {
		fd, err := fn()
		if !errors.Is(err, unix.EINTR) {
			return fd, err
		}
	}
}

func (f *fsReader) openAt(dirfd int, name string, flags int) (int, error) {
	flags |= unix.O_CLOEXEC | unix.O_NOFOLLOW
	if !f.noOpenat2.Load() {
		how := &unix.OpenHow{
			Flags:   uint64(flags),
			Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_BENEATH,
		}
		fd, err := retryEINTR(func() (int, error) { return unix.Openat2(dirfd, name, how) })
		if !errors.Is(err, unix.ENOSYS) {
			return fd, err
		}
		f.noOpenat2.Store(true)
	}
	return retryEINTR(func() (int, error) { return unix.Openat(dirfd, name, flags, 0) })
}

// statusOf maps an open error to a source status and its reason.
func statusOf(err error) (string, string) {
	switch {
	case errors.Is(err, unix.ENOENT):
		return statusAbsent, ""
	case errors.Is(err, unix.ELOOP), errors.Is(err, unix.EXDEV), errors.Is(err, unix.ENOTDIR),
		errors.Is(err, unix.ENXIO), errors.Is(err, unix.EOPNOTSUPP):
		return statusRejected, reasonFileRejected
	}
	return statusUnreadable, reasonFileUnreadable
}

func failed(status, reason string) loaded {
	l := loaded{status: status, reasons: reasonSet{}}
	if reason != "" {
		l.reasons.add(reason)
	}
	return l
}

// walkDirs opens every directory of p's parent chain and returns the
// descriptor of the parent with the stats of each directory from the root.
// The caller closes the descriptor unless it is the root's.
func (f *fsReader) walkDirs(p string, rule ownerRule, includeLast bool) (int, string, []pathStat, loaded, bool) {
	if p != "/" && !validPath(p) {
		return -1, "", nil, failed(statusUnresolved, reasonPathTokenUnresolved), false
	}
	comps := strings.Split(strings.TrimPrefix(p, "/"), "/")
	if p == "/" {
		comps = nil
	}
	last := ""
	if !includeLast && len(comps) > 0 {
		last, comps = comps[len(comps)-1], comps[:len(comps)-1]
	}
	stats := []pathStat{{path: "/", uid: f.mapOwner("/", f.root.Uid), mode: f.root.Mode}}
	if rule.system && stats[0].uid != 0 {
		return -1, "", nil, failed(statusRejected, reasonFileRejected), false
	}
	cur := f.rootFD
	prefix := ""
	parents := []int{cur}
	paths := []string{""}
	trusted := stats[0].uid == 0 && stats[0].mode&0o022 == 0
	hops := 0
	keepFD := -1
	defer func() {
		for _, fd := range parents[1:] {
			if fd != keepFD {
				_ = unix.Close(fd)
			}
		}
	}()
	for len(comps) > 0 {
		c := comps[0]
		comps = comps[1:]
		if c == "" || c == "." {
			continue
		}
		if c == ".." {
			if len(parents) > 1 {
				_ = unix.Close(cur)
				parents, paths = parents[:len(parents)-1], paths[:len(paths)-1]
				stats = stats[:len(stats)-1]
				cur, prefix = parents[len(parents)-1], paths[len(paths)-1]
			}
			continue
		}
		next := prefix + "/" + c
		if testHookOpen != nil {
			if err := testHookOpen(next); err != nil {
				return -1, "", nil, failed(statusOf(err)), false
			}
		}
		if trusted {
			var st unix.Stat_t
			if err := unix.Fstatat(cur, c, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return -1, "", nil, failed(statusOf(err)), false
			}
			if st.Mode&unix.S_IFMT == unix.S_IFLNK {
				var parent unix.Stat_t
				if err := unix.Fstat(cur, &parent); err != nil {
					return -1, "", nil, failed(statusUnreadable, reasonFileUnreadable), false
				}
				hops++
				if f.mapOwner(next, st.Uid) != 0 || f.mapOwner(stats[len(stats)-1].path, parent.Uid) != 0 || parent.Mode&0o022 != 0 || hops > 40 {
					return -1, "", nil, failed(statusRejected, reasonFileRejected), false
				}
				buf := make([]byte, unix.PathMax+1)
				n, err := unix.Readlinkat(cur, c, buf)
				if err != nil {
					return -1, "", nil, failed(statusOf(err)), false
				}
				if n == len(buf) {
					return -1, "", nil, failed(statusRejected, reasonFileRejected), false
				}
				target := string(buf[:n])
				if strings.HasPrefix(target, "/") {
					for _, fd := range parents[1:] {
						_ = unix.Close(fd)
					}
					parents, paths = parents[:1], paths[:1]
					stats = stats[:1]
					cur, prefix = f.rootFD, ""
				}
				comps = append(strings.Split(target, "/"), comps...)
				continue
			}
		}
		fd, err := f.openAt(cur, c, unix.O_RDONLY|unix.O_DIRECTORY)
		if err != nil {
			return -1, "", nil, failed(statusOf(err)), false
		}
		cur, prefix = fd, next
		parents, paths = append(parents, cur), append(paths, prefix)
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			return -1, "", nil, failed(statusUnreadable, reasonFileUnreadable), false
		}
		ps := pathStat{path: prefix, uid: f.mapOwner(prefix, st.Uid), mode: st.Mode}
		if rule.system && ps.uid != 0 {
			return -1, "", nil, failed(statusRejected, reasonFileRejected), false
		}
		stats = append(stats, ps)
		trusted = trusted && ps.uid == 0 && ps.mode&0o022 == 0
	}
	keepFD = cur
	return cur, last, stats, loaded{status: statusRead, reasons: reasonSet{}}, true
}

// openRegular opens p for reading and validates the descriptor: a regular
// file, owned as rule allows, with one hard link for an account source. A
// FIFO or device is never opened for reading: the first open is O_PATH, and
// the read descriptor is checked to be the same inode.
func (f *fsReader) openRegular(p string, rule ownerRule) (*os.File, unix.Stat_t, []pathStat, loaded) {
	var st unix.Stat_t
	dirfd, last, dirs, l, ok := f.walkDirs(p, rule, false)
	if !ok {
		return nil, st, nil, l
	}
	defer func() {
		if dirfd != f.rootFD {
			_ = unix.Close(dirfd)
		}
	}()
	if testHookOpen != nil {
		if err := testHookOpen(p); err != nil {
			return nil, st, dirs, failed(statusOf(err))
		}
	}
	pathFD, err := f.openAt(dirfd, last, unix.O_PATH)
	if err != nil {
		return nil, st, dirs, failed(statusOf(err))
	}
	defer func() { _ = unix.Close(pathFD) }()
	if err := unix.Fstat(pathFD, &st); err != nil {
		return nil, st, dirs, failed(statusUnreadable, reasonFileUnreadable)
	}
	if testHookFstat != nil {
		testHookFstat(p, &st)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || !rule.allows(f.mapOwner(p, st.Uid)) || (!rule.system && st.Nlink != 1) {
		return nil, st, dirs, failed(statusRejected, reasonFileRejected)
	}
	// Ownership alone cannot distinguish a root-owned orphaned hard link
	// from its original secret. In an account-controlled parent chain only
	// root files already readable by everyone are safe to parse.
	if !rule.system && f.mapOwner(p, st.Uid) == 0 && st.Mode&0o004 == 0 {
		for _, dir := range dirs {
			if dir.uid != 0 || dir.mode&0o022 != 0 {
				return nil, st, dirs, failed(statusRejected, reasonFileRejected)
			}
		}
	}
	fd, err := f.openAt(dirfd, last, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY)
	if err != nil {
		return nil, st, dirs, failed(statusOf(err))
	}
	var st2 unix.Stat_t
	if err := unix.Fstat(fd, &st2); err != nil || st2.Dev != st.Dev || st2.Ino != st.Ino {
		_ = unix.Close(fd)
		return nil, st, dirs, failed(statusRead, reasonConcurrentChange)
	}
	return os.NewFile(uintptr(fd), p), st, dirs, loaded{status: statusRead, reasons: reasonSet{}}
}

func mtimeOf(st *unix.Stat_t) time.Time {
	return time.Unix(st.Mtim.Sec, st.Mtim.Nsec)
}

func changed(a, b *unix.Stat_t) bool {
	return a.Size != b.Size || a.Mtim != b.Mtim
}

// read reads p in full. Content is returned only when the file was read to
// its end within maxReadBytes and did not change while it was read.
func (f *fsReader) read(p string, rule ownerRule) (loaded, []pathStat) {
	file, st, dirs, l := f.openRegular(p, rule)
	if file == nil {
		return l, dirs
	}
	defer func() { _ = file.Close() }()
	l.mtime, l.uid, l.mode = mtimeOf(&st), f.mapOwner(p, st.Uid), st.Mode
	if testHookRead != nil {
		testHookRead(p)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxReadBytes+1))
	if err != nil {
		clear(data)
		l.status = statusUnreadable
		l.reasons.add(reasonFileUnreadable)
		return l, dirs
	}
	if testHookAfterRead != nil {
		testHookAfterRead(p)
	}
	var after unix.Stat_t
	statErr := unix.Fstat(int(file.Fd()), &after)
	switch {
	case len(data) > maxReadBytes:
		l.reasons.add(reasonLimitExceeded)
	case statErr != nil || changed(&st, &after) || int64(len(data)) != st.Size:
		l.reasons.add(reasonConcurrentChange)
	default:
		l.data = data
		return l, dirs
	}
	clear(data)
	return l, dirs
}

// readTail reads at most maxReadBytes of whole records from the end of a
// root-owned file. A file longer than that is marked limit_exceeded and its
// tail is still returned: the newest records are at the end.
func (f *fsReader) readTail(p string, record int64) loaded {
	file, st, _, l := f.openRegular(p, ownerRule{system: true})
	if file == nil {
		return l
	}
	defer func() { _ = file.Close() }()
	l.mtime = mtimeOf(&st)
	window := int64(maxReadBytes) / record * record
	offset := int64(0)
	if st.Size > window {
		offset = (st.Size - window + record - 1) / record * record
		l.reasons.add(reasonLimitExceeded)
	}
	if testHookRead != nil {
		testHookRead(p)
	}
	data, err := io.ReadAll(io.NewSectionReader(file, offset, window))
	if err != nil {
		l.status = statusUnreadable
		l.reasons.add(reasonFileUnreadable)
		return l
	}
	var after unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &after); err != nil || changed(&st, &after) {
		clear(data)
		l.reasons.add(reasonConcurrentChange)
		return l
	}
	l.data = data
	return l
}

// readRecords reads fixed-size records at the given offsets of a root-owned
// file, for lastlog, which is indexed by uid and usually sparse.
func (f *fsReader) readRecords(p string, size int64, offsets []int64) (loaded, map[int64][]byte) {
	file, st, _, l := f.openRegular(p, ownerRule{system: true})
	if file == nil {
		return l, nil
	}
	defer func() { _ = file.Close() }()
	if testHookRead != nil {
		testHookRead(p)
	}
	out := map[int64][]byte{}
	for _, off := range offsets {
		if off < 0 || off+size > st.Size {
			continue
		}
		buf := make([]byte, size)
		if _, err := file.ReadAt(buf, off); err != nil {
			l.status = statusUnreadable
			l.reasons.add(reasonFileUnreadable)
			return l, nil
		}
		out[off] = buf
	}
	var after unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &after); err != nil || changed(&st, &after) {
		l.reasons.add(reasonConcurrentChange)
		return l, nil
	}
	l.data = []byte{}
	return l, out
}

// statDir walks to directory p and returns the stats of every component,
// p's own last.
func (f *fsReader) statDir(p string, rule ownerRule) ([]pathStat, loaded) {
	fd, _, stats, l, ok := f.walkDirs(p, rule, true)
	if !ok {
		return nil, l
	}
	if fd != f.rootFD {
		_ = unix.Close(fd)
	}
	return stats, l
}

// list returns the entry names of directory p.
func (f *fsReader) list(p string, rule ownerRule, recordsOnly ...bool) ([]string, loaded) {
	fd, _, _, l, ok := f.walkDirs(p, rule, true)
	if !ok {
		return nil, l
	}
	if fd == f.rootFD {
		dup, err := unix.Dup(fd)
		if err != nil {
			return nil, failed(statusUnreadable, reasonFileUnreadable)
		}
		fd = dup
	}
	dir := os.NewFile(uintptr(fd), p)
	defer func() { _ = dir.Close() }()
	names, err := dir.Readdirnames(maxDirEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, failed(statusUnreadable, reasonFileUnreadable)
	}
	if len(names) > maxDirEntries {
		l.reasons.add(reasonLimitExceeded)
		return nil, l
	}
	if len(recordsOnly) > 0 && recordsOnly[0] {
		files := names[:0]
		for _, name := range names {
			var st unix.Stat_t
			if err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return nil, failed(statusUnreadable, reasonFileUnreadable)
			}
			if kind := st.Mode & unix.S_IFMT; kind == unix.S_IFREG || kind == unix.S_IFLNK {
				files = append(files, name)
			}
		}
		names = files
	}
	l.data = []byte{}
	return names, l
}

// exists reports whether p's last component exists, without following it,
// so an enablement symlink counts as present.
func (f *fsReader) exists(p string) (bool, loaded) {
	fd, last, _, l, ok := f.walkDirs(p, ownerRule{system: true}, false)
	if !ok {
		return false, l
	}
	defer func() {
		if fd != f.rootFD {
			_ = unix.Close(fd)
		}
	}()
	var st unix.Stat_t
	err := unix.Fstatat(fd, last, &st, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		return true, l
	}
	status, reason := statusOf(err)
	if status == statusAbsent {
		return false, loaded{status: statusAbsent, reasons: reasonSet{}}
	}
	return false, failed(status, reason)
}

// systemFiles adapts the reader to systemSource for root-owned sources.
type systemFiles struct{ f *fsReader }

func (s systemFiles) load(p string) loaded {
	l, _ := s.f.read(p, ownerRule{system: true})
	return l
}

func (s systemFiles) list(p string) ([]string, loaded) {
	return s.f.list(p, ownerRule{system: true})
}
