package exposure

import (
	"maps"
	"slices"
)

const maxObservationRows = 20000

// reportForVersion copies the containers that finalization edits.
func reportForVersion(snapshot *exposureReport, version int) *exposureReport {
	r := *snapshot
	r.SchemaVersion = version
	r.Categories = maps.Clone(snapshot.Categories)
	r.Accounts = slices.Clone(snapshot.Accounts)
	for i := range r.Accounts {
		a := &r.Accounts[i]
		a.KeyFiles = slices.Clone(a.KeyFiles)
		a.PrincipalsFiles = slices.Clone(a.PrincipalsFiles)
		a.TrustFiles = slices.Clone(a.TrustFiles)
	}
	if r.UserCA != nil {
		r.UserCA = ptr(*r.UserCA)
	}
	r.SystemTrust = slices.Clone(snapshot.SystemTrust)
	return &r
}

// finalize limits each account before applying the row and byte caps. Sources are
// cut largest first, with path order breaking ties, then the report is sealed.
func finalize(r *exposureReport) ([]byte, error) {
	readHook("finalize")
	retainedAccounts := r.Accounts[:0]
	for i := range r.Accounts {
		a := &r.Accounts[i]
		if r.encodedLen(a) <= maxAccountBytes {
			retainedAccounts = append(retainedAccounts, *a)
			continue
		}
		for _, source := range accountCuts(r, a) {
			source.cut()
			if r.encodedLen(a) <= maxAccountBytes {
				break
			}
		}
		if r.encodedLen(a) <= maxAccountBytes {
			retainedAccounts = append(retainedAccounts, *a)
		} else {
			markCut(r, catAccounts)
		}
	}
	r.Accounts = retainedAccounts
	capObservationRows(r)
	body, err := serializeReport(r)
	if err != nil || len(body) <= maxReportBytes {
		return body, err
	}
	var sources []sourceCut
	for i := range r.Accounts {
		sources = append(sources, accountCuts(r, &r.Accounts[i])...)
	}
	if r.UserCA != nil && len(r.UserCA.CAs) > 0 {
		u := r.UserCA
		sources = append(sources, sourceCut{len(u.CAs), r.encodedLen(u), u.Path, func() { u.CAs = []caKey{}; cutEnvelope(&u.envelope); markCut(r, catCertificates) }, u})
	}
	for i := range r.SystemTrust {
		s := &r.SystemTrust[i]
		if len(s.Entries) > 0 {
			sources = append(sources, sourceCut{len(s.Entries), r.encodedLen(s), s.Path, func() { s.Entries = []hostUser{}; cutEnvelope(&s.envelope); markCut(r, catTrust) }, s})
		}
	}
	sortCuts(sources)
	size := len(body)
	for _, source := range sources {
		beforeCategories := r.encodedLen(r.Categories)
		source.cut()
		size -= source.size - r.encodedLen(source.value)
		size += r.encodedLen(r.Categories) - beforeCategories
		if size <= maxReportBytes {
			return serializeReport(r)
		}
	}

	// If source envelopes and account metadata alone exceed the wire cap,
	// remove the largest remaining account, preserving every retained account.
	type accountSize struct {
		index, size int
		name        string
	}
	remaining := make([]accountSize, len(r.Accounts))
	for i := range r.Accounts {
		remaining[i] = accountSize{i, r.encodedLen(r.Accounts[i]), r.Accounts[i].Username}
	}
	slices.SortFunc(remaining, func(a, b accountSize) int {
		if a.size != b.size {
			return b.size - a.size
		}
		if a.name < b.name {
			return -1
		}
		if a.name > b.name {
			return 1
		}
		return 0
	})
	dropped := map[int]bool{}
	beforeCategories := r.encodedLen(r.Categories)
	markCut(r, catAccounts)
	size += r.encodedLen(r.Categories) - beforeCategories
	for _, a := range remaining {
		if size <= maxReportBytes {
			break
		}
		dropped[a.index] = true
		size -= a.size + 1
	}
	retained := r.Accounts[:0]
	for i, a := range r.Accounts {
		if !dropped[i] {
			retained = append(retained, a)
		}
	}
	r.Accounts = retained
	return serializeReport(r)
}

type sourceCut struct {
	rows  int
	size  int
	path  string
	cut   func()
	value any
}

func sortCuts(cuts []sourceCut) {
	slices.SortStableFunc(cuts, func(a, b sourceCut) int {
		if a.size != b.size {
			return b.size - a.size
		}
		if a.path < b.path {
			return -1
		}
		if a.path > b.path {
			return 1
		}
		return 0
	})
}

func accountCuts(r *exposureReport, a *account) []sourceCut {
	var cuts []sourceCut
	for i := range a.KeyFiles {
		s := &a.KeyFiles[i]
		if len(s.Keys) > 0 {
			cuts = append(cuts, sourceCut{authorizationRows(s.Keys), r.encodedLen(s), s.Path, func() { s.Keys = []key{}; cutEnvelope(&s.envelope); markCut(r, catKeys) }, s})
		}
	}
	for i := range a.PrincipalsFiles {
		s := &a.PrincipalsFiles[i]
		if len(s.Entries) > 0 {
			cuts = append(cuts, sourceCut{len(s.Entries), r.encodedLen(s), s.Path, func() { s.Entries = []principalEntry{}; cutEnvelope(&s.envelope); markCut(r, catCertificates) }, s})
		}
	}
	for i := range a.TrustFiles {
		s := &a.TrustFiles[i]
		if len(s.Entries) > 0 {
			cuts = append(cuts, sourceCut{len(s.Entries), r.encodedLen(s), s.Path, func() { s.Entries = []trustEntry{}; cutEnvelope(&s.envelope); markCut(r, catTrust) }, s})
		}
	}
	if len(a.Sudo.Grants) > 0 {
		cuts = append(cuts, sourceCut{len(a.Sudo.Grants), r.encodedLen(a.Sudo), "/etc/sudoers", func() {
			a.Sudo.Grants = []grant{}
			a.Sudo.Complete = false
			a.Sudo.Reasons = appendReason(a.Sudo.Reasons, reasonLimitExceeded)
			markCut(r, catSudo)
		}, &a.Sudo})
	}
	if a.LastPTYLogin != nil {
		cuts = append(cuts, sourceCut{0, r.encodedLen(a.LastPTYLogin), "/var/log/lastlog", func() { a.LastPTYLogin = nil; markCut(r, catPTY) }, &a.LastPTYLogin})
	}
	sortCuts(cuts)
	return cuts
}

// observationRows matches the server's count, independent of stored rows.
func observationRows(r *exposureReport) int {
	rows := len(r.Accounts) + len(r.External)
	if r.UserCA != nil {
		rows += len(r.UserCA.CAs)
	}
	for _, s := range r.SystemTrust {
		rows += len(s.Entries)
	}
	for _, a := range r.Accounts {
		for _, s := range a.KeyFiles {
			rows += authorizationRows(s.Keys)
		}
		for _, s := range a.PrincipalsFiles {
			rows += len(s.Entries)
		}
		for _, s := range a.TrustFiles {
			rows += len(s.Entries)
		}
		rows += len(a.Sudo.Grants)
	}
	return rows
}

func authorizationRows(keys []key) int {
	rows := 0
	for _, k := range keys {
		rows += len(k.Authorizations)
	}
	return rows
}

func capObservationRows(r *exposureReport) {
	rows := observationRows(r)
	if rows <= maxObservationRows {
		return
	}
	type accountRows struct {
		account    *account
		rows, size int
		sources    []sourceCut
	}
	accounts := make([]accountRows, len(r.Accounts))
	for i := range r.Accounts {
		a := &r.Accounts[i]
		cuts := accountCuts(r, a)
		// accountCuts already orders equal-row sources by size and path.
		slices.SortStableFunc(cuts, func(a, b sourceCut) int { return b.rows - a.rows })
		accounts[i] = accountRows{a, observationRows(&exposureReport{Accounts: []account{*a}}), r.encodedLen(a), cuts}
	}
	for rows > maxObservationRows {
		largest := -1
		for i := range accounts {
			a := &accounts[i]
			if len(a.sources) == 0 || a.sources[0].rows == 0 {
				continue
			}
			if largest < 0 || a.rows > accounts[largest].rows ||
				(a.rows == accounts[largest].rows && (a.size > accounts[largest].size ||
					(a.size == accounts[largest].size && a.account.Username < accounts[largest].account.Username))) {
				largest = i
			}
		}
		if largest < 0 {
			break
		}
		a := &accounts[largest]
		source := a.sources[0]
		source.cut()
		rows -= source.rows
		a.rows -= source.rows
		a.size = r.encodedLen(a.account)
		a.sources = a.sources[1:]
	}
}

func (r *exposureReport) encodedLen(v any) int {
	tree, err := wireTree(v, r.SchemaVersion)
	if err != nil {
		return 0
	}
	b, err := appendCanonical(nil, tree)
	if err != nil {
		return 0
	}
	return len(b)
}

func markCut(r *exposureReport, cat string) {
	c := r.Categories[cat]
	c.Reasons = appendReason(c.Reasons, reasonLimitExceeded)
	if c.Status == coverageCovered {
		c.Status = coveragePartial
	}
	r.Categories[cat] = c
}

func cutEnvelope(e *envelope) {
	e.Complete = false
	e.Reasons = appendReason(e.Reasons, reasonLimitExceeded)
}

func serializeReport(r *exposureReport) ([]byte, error) {
	readHook("serialize")
	return seal(r)
}
