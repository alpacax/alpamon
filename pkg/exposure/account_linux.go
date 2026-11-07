//go:build linux

package exposure

import (
	"context"
	"slices"
	"strings"
)

// accountSlot survives collection attempts, including a read abandoned on a
// hung mount. The collector retains only occupied slots, with a global bound.
type accountSlot struct{ category, username string }

type accountResult[T any] struct {
	value  T
	reason string
}

func runAccountBudget[T any](ctx context.Context, c *collector, cat, user string, fn func() T) (T, string) {
	var zero T
	key := accountSlot{cat, user}
	c.accountMu.Lock()
	if c.accountBusy[key] || c.accountCount >= maxAccountWorkers || ctx.Err() != nil {
		c.accountMu.Unlock()
		return zero, reasonTimeout
	}
	c.accountBusy[key] = true
	c.accountCount++
	c.accountMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, accountBudget)
	defer cancel()
	done := make(chan accountResult[T], 1)
	go func() {
		result := accountResult[T]{}
		defer func() {
			if recover() != nil {
				result.reason = reasonParseError
				logParserPanic(cat)
			}
			c.accountMu.Lock()
			delete(c.accountBusy, key)
			c.accountCount--
			c.accountMu.Unlock()
			done <- result
		}()
		result.value = fn()
	}()
	select {
	case result := <-done:
		return result.value, result.reason
	case <-ctx.Done():
		return zero, reasonTimeout
	}
}

func categoryFailure[T any](reason string) T {
	rs := reasonSet{reason: {}}
	var out T
	switch v := any(&out).(type) {
	case *accountsData:
		v.reasons = rs
	case *shadowData:
		v.reasons = rs
	case *sshdData:
		v.reasons = rs
		v.daemon.Correspondence = "unresolved"
	case *sudoPolicy:
		v.global = rs
	case *keysData:
		v.reasons = rs
		v.failure = reason
	case *certsData:
		v.reasons = rs
		v.failure = reason
	case *trustData:
		v.reasons = rs
		v.failure = reason
	case *ptyData:
		v.reasons = rs
	}
	return out
}

func failureEnvelope(path, reason string) Envelope {
	status := statusUnresolved
	if reason == reasonTimeout {
		status = statusTimeout
	}
	return Envelope{Path: path, Status: status, Reasons: []string{reason}}
}

func failedAccountKeys(a passwdEntry, t *sshdT, reason string) accountKeys {
	out := accountKeys{home: Home{Status: statusUnresolved}, files: []KeyFile{}}
	if reason == reasonTimeout {
		out.home.Status = statusTimeout
	}
	seen := map[string]bool{}
	for _, tmpl := range strings.Fields(sshdValue(t, "authorizedkeysfile")) {
		if tmpl == "none" {
			continue
		}
		p, ok := expandPath(tmpl, a.home, a.name)
		if !ok {
			p = tmpl
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out.files = append(out.files, KeyFile{Envelope: failureEnvelope(p, reason), Keys: []Key{}})
	}
	slices.SortFunc(out.files, func(a, b KeyFile) int { return strings.Compare(a.Path, b.Path) })
	return out
}

func failedAccountCerts(a passwdEntry, t *sshdT, reason string) []PrincipalsFile {
	tmpl := sshdValue(t, "authorizedprincipalsfile")
	if tmpl == "" || tmpl == "none" {
		return []PrincipalsFile{}
	}
	p, ok := expandPath(tmpl, a.home, a.name)
	if !ok {
		p = tmpl
	}
	return []PrincipalsFile{{Envelope: failureEnvelope(p, reason), Entries: []PrincipalEntry{}}}
}

func failedAccountTrust(a passwdEntry, t *sshdT, cfg sshdConfig, reason string) []TrustFile {
	out := []TrustFile{}
	var kinds []string
	if enabledAnywhere(t, cfg, "gssapiauthentication", "yes") || enabledAnywhere(t, cfg, "kerberosauthentication", "yes") {
		kinds = append(kinds, "k5login")
	}
	if enabledAnywhere(t, cfg, "hostbasedauthentication", "yes") || enabledAnywhere(t, cfg, "ignorerhosts", "no") {
		kinds = append(kinds, "rhosts", "shosts")
	}
	for _, kind := range kinds {
		p, _ := expandPath("."+kind, a.home, a.name)
		out = append(out, TrustFile{Envelope: failureEnvelope(p, reason), Kind: kind, Entries: []TrustEntry{}})
	}
	return out
}

func (c *collector) readKeysBudget(ctx context.Context, accounts []passwdEntry, t *sshdT, cfg sshdConfig) keysData {
	d := withFS(c, categoryFailure[keysData](reasonFileUnreadable), func(fs *fsReader, _ systemFiles) keysData { return readKeys(fs, nil, t, cfg) })
	if !d.usable {
		return d
	}
	for _, a := range accounts {
		one, reason := runAccountBudget(ctx, c, catKeys, a.name, func() keysData {
			return withFS(c, categoryFailure[keysData](reasonFileUnreadable), func(fs *fsReader, _ systemFiles) keysData { return readKeys(fs, []passwdEntry{a}, t, cfg) })
		})
		if reason == "" {
			reason = one.failure
		}
		if reason != "" {
			d.byUser[a.name] = failedAccountKeys(a, t, reason)
			d.reasons.add(reason)
			continue
		}
		d.byUser[a.name] = one.byUser[a.name]
		d.reasons.merge(one.reasons)
	}
	return d
}

func (c *collector) readCertsBudget(ctx context.Context, accounts []passwdEntry, t *sshdT, cfg sshdConfig) certsData {
	d := withFS(c, categoryFailure[certsData](reasonFileUnreadable), func(fs *fsReader, sys systemFiles) certsData { return readCerts(fs, sys, nil, t, cfg) })
	if !d.usable {
		return d
	}
	if tmpl := sshdValue(t, "authorizedprincipalsfile"); tmpl == "" || tmpl == "none" {
		return d
	}
	for _, a := range accounts {
		one, reason := runAccountBudget(ctx, c, catCertificates, a.name, func() certsData {
			return withFS(c, categoryFailure[certsData](reasonFileUnreadable), func(fs *fsReader, sys systemFiles) certsData {
				return readCerts(fs, sys, []passwdEntry{a}, t, cfg, true)
			})
		})
		if reason == "" {
			reason = one.failure
		}
		if reason != "" {
			d.principals[a.name] = failedAccountCerts(a, t, reason)
			d.reasons.add(reason)
			continue
		}
		d.principals[a.name] = one.principals[a.name]
		d.reasons.merge(one.reasons)
	}
	return d
}

func (c *collector) readTrustBudget(ctx context.Context, accounts []passwdEntry, t *sshdT, cfg sshdConfig) trustData {
	d := withFS(c, categoryFailure[trustData](reasonFileUnreadable), func(fs *fsReader, sys systemFiles) trustData { return readTrust(fs, sys, nil, t, cfg) })
	if !d.usable {
		return d
	}
	if !enabledAnywhere(t, cfg, "gssapiauthentication", "yes") && !enabledAnywhere(t, cfg, "kerberosauthentication", "yes") && !enabledAnywhere(t, cfg, "hostbasedauthentication", "yes") && !enabledAnywhere(t, cfg, "ignorerhosts", "no") {
		return d
	}
	for _, a := range accounts {
		one, reason := runAccountBudget(ctx, c, catTrust, a.name, func() trustData {
			return withFS(c, categoryFailure[trustData](reasonFileUnreadable), func(fs *fsReader, sys systemFiles) trustData {
				return readTrust(fs, sys, []passwdEntry{a}, t, cfg, true)
			})
		})
		if reason == "" {
			reason = one.failure
		}
		if reason != "" {
			d.files[a.name] = failedAccountTrust(a, t, cfg, reason)
			d.reasons.add(reason)
			continue
		}
		d.files[a.name] = one.files[a.name]
		d.reasons.merge(one.reasons)
	}
	return d
}
