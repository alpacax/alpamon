//go:build linux

package exposure

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"
)

// accountSlot survives collection attempts, including a read abandoned on a
// hung mount. The global bound counts abandoned workers, in addition to
// each category's in-flight slots.
type accountSlot struct{ category, username string }

type accountResult[T any] struct {
	value  T
	reason string
}

func runAccountBudget[T any](ctx context.Context, c *collector, cat, user string, fn func() T) (T, string, bool) {
	var zero T
	budget := accountBudget
	if deadline, ok := ctx.Deadline(); ok {
		budget = min(budget, time.Until(deadline)-accountReturnMargin)
	}
	if budget <= 0 {
		return zero, reasonTimeout, false
	}
	key := accountSlot{cat, user}
	c.accountMu.Lock()
	if c.accountBusy[key] || ctx.Err() != nil {
		c.accountMu.Unlock()
		return zero, reasonTimeout, false
	}
	if c.accountInFlight[cat] >= maxConcurrentAccounts {
		c.accountMu.Unlock()
		return zero, reasonTimeout, true
	}
	c.accountBusy[key] = true
	c.accountInFlight[cat]++
	completed, abandoned := false, false
	c.accountMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	done := make(chan accountResult[T], 1)
	releaseFS := retainCollectionFS(ctx)
	go func() {
		result := accountResult[T]{}
		defer func() {
			if recover() != nil {
				result.reason = reasonParseError
				logParserPanic(cat)
			}
			releaseFS()
			c.accountMu.Lock()
			completed = true
			delete(c.accountBusy, key)
			if abandoned {
				c.accountCount--
			} else {
				c.accountInFlight[cat]--
			}
			c.accountMu.Unlock()
			done <- result
		}()
		result.value = fn()
	}()
	select {
	case result := <-done:
		return result.value, result.reason, false
	case <-ctx.Done():
		c.accountMu.Lock()
		defer c.accountMu.Unlock()
		if completed {
			return zero, reasonTimeout, false
		}
		if c.accountCount >= maxAccountWorkers {
			// Retain this in-flight lane until its worker exits.
			return zero, reasonTimeout, true
		}
		abandoned = true
		c.accountCount++
		c.accountInFlight[cat]--
		return zero, reasonTimeout, false
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
		v.failed = true
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

func failureEnvelope(path, reason string) envelope {
	status := statusUnresolved
	if reason == reasonTimeout {
		status = statusTimeout
	}
	return envelope{Path: path, Status: status, Reasons: []string{reason}}
}

func failedAccountKeys(a passwdEntry, t *sshdT, reason string) accountKeys {
	out := accountKeys{home: home{Status: statusUnresolved}, files: []keyFile{}}
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
			if a.home == "" {
				continue
			}
			p = tmpl
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out.files = append(out.files, keyFile{envelope: failureEnvelope(p, reason), Keys: []key{}})
	}
	slices.SortFunc(out.files, func(a, b keyFile) int { return strings.Compare(a.Path, b.Path) })
	return out
}

func failedAccountCerts(a passwdEntry, t *sshdT, reason string) []principalsFile {
	tmpl := sshdValue(t, "authorizedprincipalsfile")
	if tmpl == "" || tmpl == "none" {
		return []principalsFile{}
	}
	p, ok := expandPath(tmpl, a.home, a.name)
	if !ok {
		if a.home == "" {
			return []principalsFile{}
		}
		p = tmpl
	}
	return []principalsFile{{envelope: failureEnvelope(p, reason), Entries: []principalEntry{}}}
}

func failedAccountTrust(a passwdEntry, t *sshdT, cfg sshdConfig, reason string) []trustFile {
	out := []trustFile{}
	if a.home == "" {
		return out
	}
	var kinds []string
	if enabledAnywhere(t, cfg, "gssapiauthentication", "yes") || enabledAnywhere(t, cfg, "kerberosauthentication", "yes") {
		kinds = append(kinds, "k5login")
	}
	if enabledAnywhere(t, cfg, "hostbasedauthentication", "yes") || enabledAnywhere(t, cfg, "ignorerhosts", "no") {
		kinds = append(kinds, "rhosts", "shosts")
	}
	for _, kind := range kinds {
		p, _ := expandPath("."+kind, a.home, a.name)
		out = append(out, trustFile{envelope: failureEnvelope(p, reason), Kind: kind, Entries: []trustEntry{}})
	}
	return out
}

// readAccountResults keeps at most four account attempts in flight. A timeout frees
// its lane only when the worker can join the abandoned bound; otherwise that
// lane stops, and the worker retains its in-flight slot until it exits.
func readAccountResults[T any](ctx context.Context, c *collector, cat string, accounts []passwdEntry, read func(passwdEntry) T, apply func(passwdEntry, T, string)) {
	type result struct {
		account passwdEntry
		value   T
		reason  string
	}
	done := make(chan result, len(accounts))
	next := 0
	// Retained workers already occupy lanes on later reads.
	c.accountMu.Lock()
	lanes := maxConcurrentAccounts - c.accountInFlight[cat]
	c.accountMu.Unlock()
	var wg sync.WaitGroup
	for range lanes {
		wg.Add(1)
		go func() {
			current := -1
			defer wg.Done()
			defer func() {
				if recover() != nil {
					logExposurePanic(cat, "Exposure account dispatcher panicked.")
					if current >= 0 {
						var zero T
						done <- result{accounts[current], zero, reasonTimeout}
					}
				}
			}()
			for {
				c.accountMu.Lock()
				if c.accountInFlight[cat] >= maxConcurrentAccounts || next >= len(accounts) {
					c.accountMu.Unlock()
					return
				}
				current = next
				next++
				c.accountMu.Unlock()
				a := accounts[current]
				readHook("account_dispatch:" + cat)
				v, reason, stopped := runAccountBudget(ctx, c, cat, a.name, func() T { return read(a) })
				done <- result{a, v, reason}
				current = -1
				if stopped {
					return
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		for _, a := range accounts[next:] {
			var zero T
			done <- result{a, zero, reasonTimeout}
		}
		close(done)
	}()
	for r := range done {
		apply(r.account, r.value, r.reason)
	}
}

func (c *collector) readKeysBudget(ctx context.Context, accounts []passwdEntry, t *sshdT, cfg sshdConfig) keysData {
	d := withFS(ctx, c, categoryFailure[keysData](reasonFileUnreadable), func(fs *fsReader, _ systemFiles) keysData { return readKeys(fs, nil, t, cfg) })
	if !d.usable {
		return d
	}
	readAccountResults(ctx, c, catKeys, accounts, func(a passwdEntry) keysData {
		return withFS(ctx, c, categoryFailure[keysData](reasonFileUnreadable), func(fs *fsReader, _ systemFiles) keysData { return readKeys(fs, []passwdEntry{a}, t, cfg) })
	}, func(a passwdEntry, one keysData, reason string) {
		if reason == "" {
			reason = one.failure
		}
		if reason != "" {
			d.byUser[a.name] = failedAccountKeys(a, t, reason)
			d.reasons.add(reason)
			return
		}
		d.byUser[a.name] = one.byUser[a.name]
		d.reasons.merge(one.reasons)
	})
	return d
}

func (c *collector) readCertsBudget(ctx context.Context, accounts []passwdEntry, t *sshdT, cfg sshdConfig) certsData {
	d := withFS(ctx, c, categoryFailure[certsData](reasonFileUnreadable), func(fs *fsReader, sys systemFiles) certsData { return readCerts(fs, sys, nil, t, cfg, false) })
	if !d.usable {
		return d
	}
	if tmpl := sshdValue(t, "authorizedprincipalsfile"); tmpl == "" || tmpl == "none" {
		return d
	}
	readAccountResults(ctx, c, catCertificates, accounts, func(a passwdEntry) certsData {
		return withFS(ctx, c, categoryFailure[certsData](reasonFileUnreadable), func(fs *fsReader, sys systemFiles) certsData {
			return readCerts(fs, sys, []passwdEntry{a}, t, cfg, true)
		})
	}, func(a passwdEntry, one certsData, reason string) {
		if reason == "" {
			reason = one.failure
		}
		if reason != "" {
			d.principals[a.name] = failedAccountCerts(a, t, reason)
			d.reasons.add(reason)
			return
		}
		d.principals[a.name] = one.principals[a.name]
		d.reasons.merge(one.reasons)
	})
	return d
}

func (c *collector) readTrustBudget(ctx context.Context, accounts []passwdEntry, t *sshdT, cfg sshdConfig) trustData {
	d := withFS(ctx, c, categoryFailure[trustData](reasonFileUnreadable), func(fs *fsReader, sys systemFiles) trustData { return readTrust(fs, sys, nil, t, cfg, false) })
	if !d.usable {
		return d
	}
	if !enabledAnywhere(t, cfg, "gssapiauthentication", "yes") && !enabledAnywhere(t, cfg, "kerberosauthentication", "yes") && !enabledAnywhere(t, cfg, "hostbasedauthentication", "yes") && !enabledAnywhere(t, cfg, "ignorerhosts", "no") {
		return d
	}
	readAccountResults(ctx, c, catTrust, accounts, func(a passwdEntry) trustData {
		return withFS(ctx, c, categoryFailure[trustData](reasonFileUnreadable), func(fs *fsReader, sys systemFiles) trustData {
			return readTrust(fs, sys, []passwdEntry{a}, t, cfg, true)
		})
	}, func(a passwdEntry, one trustData, reason string) {
		if reason == "" {
			reason = one.failure
		}
		if reason != "" {
			d.files[a.name] = failedAccountTrust(a, t, cfg, reason)
			d.reasons.add(reason)
			return
		}
		d.files[a.name] = one.files[a.name]
		d.reasons.merge(one.reasons)
	})
	return d
}
