package exposure

import "slices"

// finalize limits each account before applying the global cap. Sources are
// cut largest first, with path order breaking ties, then the report is sealed.
func finalize(r *Report) ([]byte, error) {
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
	body, err := seal(r)
	if err != nil || len(body) <= maxReportBytes {
		return body, err
	}
	var sources []sourceCut
	for i := range r.Accounts {
		sources = append(sources, accountCuts(r, &r.Accounts[i])...)
	}
	if r.UserCA != nil && len(r.UserCA.CAs) > 0 {
		u := r.UserCA
		sources = append(sources, sourceCut{encodedLen(u), u.Path, func() { u.CAs = []CA{}; cutEnvelope(&u.Envelope); markCut(r, catCertificates) }, u})
	}
	for i := range r.SystemTrust {
		s := &r.SystemTrust[i]
		if len(s.Entries) > 0 {
			sources = append(sources, sourceCut{encodedLen(s), s.Path, func() { s.Entries = []HostUser{}; cutEnvelope(&s.Envelope); markCut(r, catTrust) }, s})
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
			return seal(r)
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
	return seal(r)
}

type sourceCut struct {
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

func accountCuts(r *Report, a *Account) []sourceCut {
	var cuts []sourceCut
	for i := range a.KeyFiles {
		s := &a.KeyFiles[i]
		if len(s.Keys) > 0 {
			cuts = append(cuts, sourceCut{encodedLen(s), s.Path, func() { s.Keys = []Key{}; cutEnvelope(&s.Envelope); markCut(r, catKeys) }, s})
		}
	}
	for i := range a.PrincipalsFiles {
		s := &a.PrincipalsFiles[i]
		if len(s.Entries) > 0 {
			cuts = append(cuts, sourceCut{encodedLen(s), s.Path, func() { s.Entries = []PrincipalEntry{}; cutEnvelope(&s.Envelope); markCut(r, catCertificates) }, s})
		}
	}
	for i := range a.TrustFiles {
		s := &a.TrustFiles[i]
		if len(s.Entries) > 0 {
			cuts = append(cuts, sourceCut{encodedLen(s), s.Path, func() { s.Entries = []TrustEntry{}; cutEnvelope(&s.Envelope); markCut(r, catTrust) }, s})
		}
	}
	if len(a.Sudo.Grants) > 0 {
		cuts = append(cuts, sourceCut{encodedLen(a.Sudo), "/etc/sudoers", func() {
			a.Sudo.Grants = []Grant{}
			a.Sudo.Complete = false
			a.Sudo.Reasons = appendSortedUnique(a.Sudo.Reasons, reasonLimitExceeded)
			markCut(r, catSudo)
		}, &a.Sudo})
	}
	if a.LastPTYLogin != nil {
		cuts = append(cuts, sourceCut{encodedLen(a.LastPTYLogin), "/var/log/lastlog", func() { a.LastPTYLogin = nil; markCut(r, catPTY) }, &a.LastPTYLogin})
	}
	sortCuts(cuts)
	return cuts
}

func encodedLen(v any) int {
	b, err := encodeValue(v)
	if err != nil {
		return 0
	}
	return len(b)
}

func markCut(r *Report, cat string) {
	c := r.Categories[cat]
	c.Reasons = appendSortedUnique(c.Reasons, reasonLimitExceeded)
	if c.Status == coverageCovered {
		c.Status = coveragePartial
	}
	r.Categories[cat] = c
}

func cutEnvelope(e *Envelope) {
	e.Complete = false
	e.Reasons = appendSortedUnique(e.Reasons, reasonLimitExceeded)
}

func containsString(list []string, s string) bool { return slices.Contains(list, s) }

func appendSortedUnique(list []string, s string) []string {
	if containsString(list, s) {
		return list
	}
	return appendSorted(list, s)
}

func appendSorted(list []string, s string) []string {
	out := append(append([]string{}, list...), s)
	slices.Sort(out)
	return out
}
