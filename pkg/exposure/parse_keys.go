package exposure

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"math/bits"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// keyOptionTakesValue lists OpenSSH's authorized_keys options, lowercase,
// and whether each takes a quoted value.
var keyOptionTakesValue = map[string]bool{
	"agent-forwarding": false, "cert-authority": false, "command": true,
	"environment": true, "expiry-time": true, "from": true,
	"no-agent-forwarding": false, "no-port-forwarding": false, "no-pty": false,
	"no-user-rc": false, "no-x11-forwarding": false, "permitlisten": true,
	"permitopen": true, "port-forwarding": false, "principals": true, "pty": false,
	"no-touch-required": false, "verify-required": false, "restrict": false,
	"tunnel": true, "user-rc": false, "x11-forwarding": false,
}

// keyOptions is what an option list may contribute to the report. Values of
// every other option are skipped by the parser and never stored.
type keyOptions struct {
	names         []string
	from          *string
	principals    []string
	hasPrincipals bool
	expiry        *string
	certAuthority bool
}

// parseKeyOptions parses an option list at the start of s and returns the
// remainder after it. It fails on an unknown option, a flag with a value, a
// value option without one, or a value outside the allowlisted grammar.
func parseKeyOptions(s []byte) (keyOptions, []byte, bool) {
	var opts keyOptions
	seen := map[string]bool{}
	i := 0
	for {
		start := i
		for i < len(s) && (isAlnum(s[i]) || s[i] == '-') {
			i++
		}
		if i == start {
			return keyOptions{}, nil, false
		}
		name := strings.ToLower(string(s[start:i]))
		takesValue, known := keyOptionTakesValue[name]
		if !known {
			return keyOptions{}, nil, false
		}
		var value []byte
		hasValue := false
		if i < len(s) && s[i] == '=' {
			i++
			if i >= len(s) || s[i] != '"' {
				return keyOptions{}, nil, false
			}
			i++
			var buf []byte
			for {
				if i >= len(s) {
					return keyOptions{}, nil, false
				}
				if s[i] == '\\' && i+1 < len(s) && s[i+1] == '"' {
					buf = append(buf, '"')
					i += 2
					continue
				}
				if s[i] == '"' {
					i++
					break
				}
				buf = append(buf, s[i])
				i++
			}
			value, hasValue = buf, true
		}
		if takesValue != hasValue {
			return keyOptions{}, nil, false
		}
		switch name {
		case "from":
			v := string(value)
			if !validFrom(v) {
				return keyOptions{}, nil, false
			}
			opts.from = &v
		case "principals":
			list, ok := parsePrincipalList(string(value))
			if !ok {
				return keyOptions{}, nil, false
			}
			opts.principals, opts.hasPrincipals = list, true
		case "expiry-time":
			v := string(value)
			if !validExpiry(v) {
				return keyOptions{}, nil, false
			}
			opts.expiry = &v
		case "cert-authority":
			opts.certAuthority = true
		}
		// Every other value (command=, environment=, permitopen=, ...) is
		// dropped here; only the option name survives.
		clear(value)
		if !seen[name] {
			seen[name] = true
			opts.names = append(opts.names, name)
		}
		if i >= len(s) || s[i] == ' ' || s[i] == '\t' {
			break
		}
		if s[i] != ',' {
			return keyOptions{}, nil, false
		}
		i++
	}
	slices.Sort(opts.names)
	return opts, s[i:], true
}

func parsePrincipalList(v string) ([]string, bool) {
	var out []string
	for p := range strings.SplitSeq(v, ",") {
		if !validPrincipal(p) || len(out) >= maxPrincipals {
			return nil, false
		}
		out = append(out, p)
	}
	return out, len(out) > 0
}

// validExpiry is OpenSSH's YYYYMMDD[HHMM[SS]] with an optional Z.
func validExpiry(v string) bool {
	d := strings.TrimSuffix(v, "Z")
	if len(d) != 8 && len(d) != 12 && len(d) != 14 {
		return false
	}
	for i := 0; i < len(d); i++ {
		if d[i] < '0' || d[i] > '9' {
			return false
		}
	}
	return true
}

// publicKey is the metadata derived from one key blob. The blob itself is
// hashed for the fingerprint and dropped.
type publicKey struct {
	fingerprint string
	keyType     string
	bits        int
}

// parseKeyBlob decodes a base64 public key blob of the given type.
func parseKeyBlob(keyType string, b64 []byte) (publicKey, bool) {
	// Sized for the unpadded form, which never decodes to less.
	blob := make([]byte, max(base64.StdEncoding.DecodedLen(len(b64)), base64.RawStdEncoding.DecodedLen(len(b64))))
	n, err := base64.StdEncoding.Decode(blob, b64)
	if err != nil {
		n, err = base64.RawStdEncoding.Decode(blob, b64)
		if err != nil {
			return publicKey{}, false
		}
	}
	blob = blob[:n]
	defer clear(blob)
	bitLen, ok := keyBits(keyType, blob)
	if !ok {
		return publicKey{}, false
	}
	sum := sha256.Sum256(blob)
	return publicKey{
		fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]),
		keyType:     keyType,
		bits:        bitLen,
	}, true
}

type sshReader struct{ b []byte }

func (r *sshReader) str() ([]byte, bool) {
	if len(r.b) < 4 {
		return nil, false
	}
	n := binary.BigEndian.Uint32(r.b)
	if uint64(n) > uint64(len(r.b)-4) {
		return nil, false
	}
	s := r.b[4 : 4+n]
	r.b = r.b[4+n:]
	return s, true
}

func mpintBits(m []byte) int {
	for len(m) > 0 && m[0] == 0 {
		m = m[1:]
	}
	if len(m) == 0 {
		return 0
	}
	return (len(m)-1)*8 + bits.Len8(m[0])
}

var ecdsaCurveBits = map[string]int{"nistp256": 256, "nistp384": 384, "nistp521": 521}

// keyBits walks the blob's wire format for keyType and returns its size.
func keyBits(keyType string, blob []byte) (int, bool) {
	r := &sshReader{b: blob}
	t, ok := r.str()
	if !ok || string(t) != keyType {
		return 0, false
	}
	fields := func(n int) ([][]byte, bool) {
		out := make([][]byte, n)
		for i := range out {
			if out[i], ok = r.str(); !ok {
				return nil, false
			}
		}
		return out, len(r.b) == 0
	}
	switch keyType {
	case "ssh-rsa":
		f, ok := fields(2)
		if !ok {
			return 0, false
		}
		return mpintBits(f[1]), mpintBits(f[1]) > 0
	case "ssh-dss":
		f, ok := fields(4)
		if !ok {
			return 0, false
		}
		return mpintBits(f[0]), mpintBits(f[0]) > 0
	case "ssh-ed25519":
		f, ok := fields(1)
		return 256, ok && len(f[0]) == 32
	case "sk-ssh-ed25519@openssh.com":
		f, ok := fields(2)
		return 256, ok && len(f[0]) == 32
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		f, ok := fields(2)
		if !ok || "ecdsa-sha2-"+string(f[0]) != keyType {
			return 0, false
		}
		return ecdsaCurveBits[string(f[0])], len(f[1]) > 0
	case "sk-ecdsa-sha2-nistp256@openssh.com":
		f, ok := fields(3)
		return 256, ok && string(f[0]) == "nistp256" && len(f[1]) > 0
	}
	return 0, false
}

var knownKeyTypes = map[string]bool{
	"ssh-rsa": true, "ssh-dss": true, "ssh-ed25519": true,
	"ecdsa-sha2-nistp256": true, "ecdsa-sha2-nistp384": true, "ecdsa-sha2-nistp521": true,
	"sk-ecdsa-sha2-nistp256@openssh.com": true, "sk-ssh-ed25519@openssh.com": true,
}

// keyLine is one parsed authorized_keys line.
type keyLine struct {
	key       publicKey
	opts      keyOptions
	comment   *string
	truncated bool
}

func cutField(s []byte) ([]byte, []byte) {
	s = bytes.TrimLeft(s, " \t")
	i := bytes.IndexAny(s, " \t")
	if i < 0 {
		return s, nil
	}
	return s[:i], s[i:]
}

// parseKeyLine parses "[options] type base64 [comment]".
func parseKeyLine(line []byte) (keyLine, bool) {
	line = bytes.TrimLeft(line, " \t")
	var kl keyLine
	first, _ := cutField(line)
	if !knownKeyTypes[string(first)] {
		opts, rest, ok := parseKeyOptions(line)
		if !ok {
			return keyLine{}, false
		}
		kl.opts, line = opts, rest
	}
	typ, rest := cutField(line)
	if !knownKeyTypes[string(typ)] {
		return keyLine{}, false
	}
	b64, rest := cutField(rest)
	key, ok := parseKeyBlob(string(typ), b64)
	if !ok {
		return keyLine{}, false
	}
	kl.key = key
	kl.comment, kl.truncated = cleanComment(rest)
	return kl, true
}

// cleanComment keeps at most maxCommentRunes runes of valid UTF-8 with
// non-printing characters removed.
func cleanComment(raw []byte) (*string, bool) {
	s := strings.TrimSpace(strings.ToValidUTF8(string(raw), ""))
	var b strings.Builder
	runes, truncated := 0, false
	for _, r := range s {
		if !unicode.IsPrint(r) || r == utf8.RuneError {
			continue
		}
		if runes == maxCommentRunes {
			truncated = true
			break
		}
		b.WriteRune(r)
		runes++
	}
	out := strings.TrimSpace(b.String())
	if out == "" {
		return nil, false
	}
	return &out, truncated
}

// authorization is the permitted metadata of one line.
func (kl keyLine) authorization() authorization {
	a := authorization{
		Count:            1,
		Role:             "user_key",
		Comment:          kl.comment,
		CommentTruncated: kl.truncated,
		Options:          kl.opts.names,
		From:             kl.opts.from,
		ExpiryTime:       kl.opts.expiry,
	}
	if a.Options == nil {
		a.Options = []string{}
	}
	if kl.opts.certAuthority {
		a.Role = "cert_authority"
		if kl.opts.hasPrincipals {
			a.Principals = kl.opts.principals
		}
	}
	return a
}

type keyFileResult struct {
	keys      []key
	unparsed  int // lines outside the grammar
	tooLong   int // lines over maxLineBytes, not looked at
	overLimit bool
}

// parseAuthorizedKeys parses an authorized_keys file. budget is the number of
// key lines the account may still contribute; it is decremented here.
func parseAuthorizedKeys(data []byte, budget *int) keyFileResult {
	var res keyFileResult
	byFP := map[string]*key{}
	variants := map[string]map[string]int{} // fingerprint -> variant -> index
	var order []string
	forEachLine(data, func(line []byte, tooLong bool) bool {
		if tooLong {
			res.tooLong++
			return true
		}
		if isBlankOrComment(line) {
			return true
		}
		kl, ok := parseKeyLine(line)
		if !ok {
			res.unparsed++
			return true
		}
		if *budget <= 0 {
			res.overLimit = true
			return false
		}
		*budget--
		k := byFP[kl.key.fingerprint]
		if k == nil {
			k = &key{Fingerprint: kl.key.fingerprint, Type: kl.key.keyType, Bits: kl.key.bits}
			byFP[kl.key.fingerprint] = k
			variants[kl.key.fingerprint] = map[string]int{}
			order = append(order, kl.key.fingerprint)
		}
		a := kl.authorization()
		id := variantID(a)
		if idx, ok := variants[k.Fingerprint][id]; ok {
			k.Authorizations[idx].Count++
		} else {
			variants[k.Fingerprint][id] = len(k.Authorizations)
			k.Authorizations = append(k.Authorizations, a)
		}
		return true
	})
	for _, fp := range order {
		k := byFP[fp]
		sortAuthorizations(k.Authorizations, variants[fp])
		res.keys = append(res.keys, *k)
	}
	slices.SortFunc(res.keys, func(a, b key) int { return strings.Compare(a.Fingerprint, b.Fingerprint) })
	return res
}

// variantID is the canonical JSON of a variant's permitted fields alone.
func variantID(a authorization) string {
	a.Count = 0
	b, _ := encodeValue(a)
	return string(b)
}

func sortAuthorizations(as []authorization, variants map[string]int) {
	keys := make([]string, len(as))
	for id, index := range variants {
		keys[index] = strings.Replace(id, `"count":0,`, `"count":`+strconv.Itoa(as[index].Count)+",", 1)
	}
	order := make([]int, len(as))
	for i := range order {
		order[i] = i
	}
	slices.SortFunc(order, func(a, b int) int { return strings.Compare(keys[a], keys[b]) })
	sorted := make([]authorization, len(as))
	for i, index := range order {
		sorted[i] = as[index]
	}
	copy(as, sorted)
}

// parseCAKeys parses a TrustedUserCAKeys file: one key per line, no options.
func parseCAKeys(data []byte) ([]caKey, int, bool) {
	seen := map[string]bool{}
	var cas []caKey
	unparsed, tooLong := 0, false
	forEachLine(data, func(line []byte, long bool) bool {
		if long {
			tooLong = true
			return true
		}
		if isBlankOrComment(line) {
			return true
		}
		kl, ok := parseKeyLine(line)
		if !ok || len(kl.opts.names) > 0 {
			unparsed++
			return true
		}
		if !seen[kl.key.fingerprint] {
			seen[kl.key.fingerprint] = true
			cas = append(cas, caKey{Fingerprint: kl.key.fingerprint, Type: kl.key.keyType, Bits: kl.key.bits})
		}
		return true
	})
	slices.SortFunc(cas, func(a, b caKey) int { return strings.Compare(a.Fingerprint, b.Fingerprint) })
	return cas, unparsed, tooLong
}

// parsePrincipalsFile parses an AuthorizedPrincipalsFile: one principal per
// line, optionally after an option list with the same grammar as keys.
func parsePrincipalsFile(data []byte) ([]principalEntry, int, bool, bool) {
	var entries []principalEntry
	seen := map[string]principalEntry{}
	unparsed, tooLong, overLimit := 0, false, false
	forEachLine(data, func(line []byte, long bool) bool {
		if long {
			tooLong = true
			return true
		}
		if isBlankOrComment(line) {
			return true
		}
		e, ok := parsePrincipalLine(line)
		if !ok {
			unparsed++
			return true
		}
		id, _ := encodeValue(e)
		if _, exists := seen[string(id)]; exists {
			return true
		}
		if len(entries) >= maxPrincipalEntries {
			overLimit = true
			return false
		}
		seen[string(id)] = e
		entries = append(entries, e)
		return true
	})
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for i, id := range ids {
		entries[i] = seen[id]
	}
	return entries, unparsed, tooLong, overLimit
}

func parsePrincipalLine(line []byte) (principalEntry, bool) {
	line = bytes.TrimSpace(line)
	e := principalEntry{Options: []string{}}
	name, rest := cutField(line)
	if len(bytes.TrimSpace(rest)) > 0 {
		// Anything after the first field means the line starts with options.
		opts, after, ok := parseKeyOptions(line)
		if !ok || opts.certAuthority || opts.hasPrincipals {
			return principalEntry{}, false
		}
		name, rest = cutField(after)
		if len(bytes.TrimSpace(rest)) > 0 {
			return principalEntry{}, false
		}
		e.Options, e.From = opts.names, opts.from
	}
	if !validPrincipal(string(name)) {
		return principalEntry{}, false
	}
	e.Principals = []string{string(name)}
	return e, true
}
