package exposure

import (
	"bytes"
	"encoding/binary"
	"time"
)

// glibc's struct utmp and struct lastlog on 64-bit Linux, where both keep
// 32-bit times for compatibility.
const (
	utmpSize        = 384
	utmpUserProcess = 7
	lastlogSize     = 292
)

// ptyRecord is a login reduced to the three fields the report carries. The
// record it came from is not kept.
type ptyRecord struct {
	time   int64
	source *string
	tty    *string
}

func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func reduceLogin(sec int64, line, host []byte) ptyRecord {
	rec := ptyRecord{time: sec}
	if tty := cString(line); validTTY(tty) {
		rec.tty = &tty
	}
	if h := cString(host); validHostname(h) {
		rec.source = &h
	}
	return rec
}

// parseWtmp returns each user's latest USER_PROCESS record. bad counts
// records that are not whole or carry an invalid user name.
func parseWtmp(data []byte, into map[string]ptyRecord) (bad int) {
	if len(data)%utmpSize != 0 {
		bad++
		data = data[:len(data)-len(data)%utmpSize]
	}
	for off := 0; off+utmpSize <= len(data); off += utmpSize {
		r := data[off : off+utmpSize]
		if int16(binary.LittleEndian.Uint16(r[0:2])) != utmpUserProcess {
			continue
		}
		user := cString(r[44:76])
		if !validName(user) {
			bad++
			continue
		}
		sec := int64(int32(binary.LittleEndian.Uint32(r[340:344])))
		if sec <= 0 {
			continue
		}
		if prev, ok := into[user]; ok && prev.time >= sec {
			continue
		}
		into[user] = reduceLogin(sec, r[8:40], r[76:332])
	}
	return bad
}

// parseLastlog decodes one lastlog record; ok is false for "never".
func parseLastlog(rec []byte) (ptyRecord, bool) {
	if len(rec) != lastlogSize {
		return ptyRecord{}, false
	}
	sec := int64(int32(binary.LittleEndian.Uint32(rec[0:4])))
	if sec <= 0 {
		return ptyRecord{}, false
	}
	return reduceLogin(sec, rec[4:36], rec[36:292]), true
}

func (p ptyRecord) login(from string) *PTYLogin {
	return &PTYLogin{
		Time:   time.Unix(p.time, 0).UTC().Format(time.RFC3339),
		Source: p.source,
		TTY:    p.tty,
		From:   from,
	}
}
