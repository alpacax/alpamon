package exposure

import "slices"

const maxObservationRows = 20000

// finalize limits each account before applying the row and byte caps. Sources are
// cut largest first, with path order breaking ties, then the report is sealed.
func finalize(r *exposureReport) ([]byte, error) {
	readHook("finalize")
	retainedAccounts := r.Accounts[:0]
	for i := range r.Accounts {
		a := &r.Accounts[i]
		if encodedLen(a) <= maxAccountBytes {
			retainedAccounts = append(retainedAccounts, *a)
			continue
		}
		for _, source := range accountCuts(r, a) {
			source.cut()
			if encodedLen(a) <= maxAccountBytes {
				break
			}
		}
		if encodedLen(a) <= maxAccountBytes {
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
		sources = append(sources, sourceCut{len(u.CAs), encodedLen(u), u.Path, func() { u.CAs = []caKey{}; cutEnvelope(&u.Envelope); markCut(r, catCertificates) }, u})
	}
	for i := range r.SystemTrust {
		s := &r.SystemTrust[i]
		if len(s.Entries) > 0 {
			sources = append(sources, sourceCut{len(s.Entries), encodedLen(s), s.Path, func() { s.Entries = []hostUser{}; cutEnvelope(&s.Envelope); markCut(r, catTrust) }, s})
		}
	}
	sortCuts(sources)
	size := len(body)
	for _, source := range sources {
		beforeCategories := encodedLen(r.Categories)
		source.cut()
		size -= source.size - encodedLen(source.value)
		size += encodedLen(r.Categories) - beforeCategories
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
		remaining[i] = accountSize{i, encodedLen(r.Accounts[i]), r.Accounts[i].Username}
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
	beforeCategories := encodedLen(r.Categories)
	markCut(r, catAccounts)
	size += encodedLen(r.Categories) - beforeCategories
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
			cuts = append(cuts, sourceCut{authorizationRows(s.Keys), encodedLen(s), s.Path, func() { s.Keys = []key{}; cutEnvelope(&s.Envelope); markCut(r, catKeys) }, s})
		}
	}
	for i := range a.PrincipalsFiles {
		s := &a.PrincipalsFiles[i]
		if len(s.Entries) > 0 {
			cuts = append(cuts, sourceCut{len(s.Entries), encodedLen(s), s.Path, func() { s.Entries = []principalEntry{}; cutEnvelope(&s.Envelope); markCut(r, catCertificates) }, s})
		}
	}
	for i := range a.TrustFiles {
		s := &a.TrustFiles[i]
		if len(s.Entries) > 0 {
			cuts = append(cuts, sourceCut{len(s.Entries), encodedLen(s), s.Path, func() { s.Entries = []trustEntry{}; cutEnvelope(&s.Envelope); markCut(r, catTrust) }, s})
		}
	}
	if len(a.Sudo.Grants) > 0 {
		cuts = append(cuts, sourceCut{len(a.Sudo.Grants), encodedLen(a.Sudo), "/etc/sudoers", func() {
			a.Sudo.Grants = []grant{}
			a.Sudo.Complete = false
			a.Sudo.Reasons = appendReason(a.Sudo.Reasons, reasonLimitExceeded)
			markCut(r, catSudo)
		}, &a.Sudo})
	}
	if a.LastPTYLogin != nil {
		cuts = append(cuts, sourceCut{0, encodedLen(a.LastPTYLogin), "/var/log/lastlog", func() { a.LastPTYLogin = nil; markCut(r, catPTY) }, &a.LastPTYLogin})
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
		accounts[i] = accountRows{a, observationRows(&exposureReport{Accounts: []account{*a}}), encodedLen(a), cuts}
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
		a.size = encodedLen(a.account)
		a.sources = a.sources[1:]
	}
}

func encodedLen(v any) int {
	b, err := encodeValue(v)
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
