package exposure

// finalize applies the report size cap, then seals the report: it sets the
// hash and returns the canonical body. When the body would exceed
// maxReportBytes, categories are cut in a fixed order (keys, certificates,
// trust, sudo, PTY history, then whole accounts) from the last account
// backwards, each cut source marked incomplete with limit_exceeded, until it
// fits. The report is still sent.
func finalize(r *Report) ([]byte, error) {
	body, err := seal(r)
	if err != nil || len(body) <= maxReportBytes {
		return body, err
	}
	size := len(body)
	for _, cut := range cutters(r) {
		if size <= maxReportBytes {
			break
		}
		size -= cut()
		if size <= maxReportBytes {
			if body, err = seal(r); err != nil {
				return nil, err
			}
			size = len(body)
		}
	}
	if body, err = seal(r); err != nil {
		return nil, err
	}
	return body, nil
}

func encodedLen(v any) int {
	b, err := encodeValue(v)
	if err != nil {
		return 0
	}
	return len(b)
}

// reasonCost is a generous allowance for the bytes a limit_exceeded marker
// and a flipped complete flag add back.
const reasonCost = len(`,"limit_exceeded"`) + 8

func markCut(r *Report, cat string) {
	c := r.Categories[cat]
	if !containsString(c.Reasons, reasonLimitExceeded) {
		c.Reasons = appendSorted(c.Reasons, reasonLimitExceeded)
	}
	if c.Status == coverageCovered {
		c.Status = coveragePartial
	}
	r.Categories[cat] = c
}

func cutEnvelope(e *Envelope) {
	e.Complete = false
	if !containsString(e.Reasons, reasonLimitExceeded) {
		e.Reasons = appendSorted(e.Reasons, reasonLimitExceeded)
	}
}

func cutters(r *Report) []func() int {
	var out []func() int
	n := len(r.Accounts)
	perAccount := func(fn func(a *Account) int) {
		for i := n - 1; i >= 0; i-- {
			out = append(out, func() int {
				if i >= len(r.Accounts) {
					return 0
				}
				return fn(&r.Accounts[i])
			})
		}
	}
	perAccount(func(a *Account) int {
		saved := 0
		for j := range a.KeyFiles {
			kf := &a.KeyFiles[j]
			if len(kf.Keys) == 0 {
				continue
			}
			saved += encodedLen(kf.Keys) - 2 - reasonCost
			kf.Keys = []Key{}
			cutEnvelope(&kf.Envelope)
			markCut(r, catKeys)
		}
		return saved
	})
	out = append(out, func() int {
		if r.UserCA == nil || len(r.UserCA.CAs) == 0 {
			return 0
		}
		saved := encodedLen(r.UserCA.CAs) - 2 - reasonCost
		r.UserCA.CAs = []CA{}
		cutEnvelope(&r.UserCA.Envelope)
		markCut(r, catCertificates)
		return saved
	})
	perAccount(func(a *Account) int {
		saved := 0
		for j := range a.PrincipalsFiles {
			pf := &a.PrincipalsFiles[j]
			if len(pf.Entries) == 0 {
				continue
			}
			saved += encodedLen(pf.Entries) - 2 - reasonCost
			pf.Entries = []PrincipalEntry{}
			cutEnvelope(&pf.Envelope)
			markCut(r, catCertificates)
		}
		return saved
	})
	perAccount(func(a *Account) int {
		saved := 0
		for j := range a.TrustFiles {
			tf := &a.TrustFiles[j]
			if len(tf.Entries) == 0 {
				continue
			}
			saved += encodedLen(tf.Entries) - 2 - reasonCost
			tf.Entries = []TrustEntry{}
			cutEnvelope(&tf.Envelope)
			markCut(r, catTrust)
		}
		return saved
	})
	perAccount(func(a *Account) int {
		if len(a.Sudo.Grants) == 0 {
			return 0
		}
		saved := encodedLen(a.Sudo.Grants) - 2 - reasonCost
		a.Sudo.Grants = []Grant{}
		a.Sudo.Complete = false
		if !containsString(a.Sudo.Reasons, reasonLimitExceeded) {
			a.Sudo.Reasons = appendSorted(a.Sudo.Reasons, reasonLimitExceeded)
		}
		markCut(r, catSudo)
		return saved
	})
	perAccount(func(a *Account) int {
		if a.LastPTYLogin == nil {
			return 0
		}
		saved := encodedLen(*a.LastPTYLogin) - len("null")
		a.LastPTYLogin = nil
		markCut(r, catPTY)
		return saved
	})
	for i := n - 1; i >= 0; i-- {
		out = append(out, func() int {
			if i >= len(r.Accounts) {
				return 0
			}
			saved := encodedLen(r.Accounts[i]) + 1
			r.Accounts = r.Accounts[:i]
			markCut(r, catAccounts)
			return saved
		})
	}
	return out
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func appendSorted(list []string, s string) []string {
	out := append(append([]string{}, list...), s)
	for i := len(out) - 1; i > 0 && out[i] < out[i-1]; i-- {
		out[i], out[i-1] = out[i-1], out[i]
	}
	return out
}
