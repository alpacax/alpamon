//go:build linux

package exposure

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccountCursorKeepsHealthyAccountsAcrossReads(t *testing.T) {
	for _, tc := range []struct {
		name       string
		hung       int
		categories []string
		reads      int
	}{
		{"six homes across categories", 6, []string{catKeys, catCertificates, catTrust}, 5},
		{"seventeen homes keys only", 17, []string{catKeys}, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c := newCollector(collectorOptions{budget: categoryBudget})
				accounts := make([]passwdEntry, tc.hung+200)
				for i := range accounts {
					accounts[i] = passwdEntry{name: fmt.Sprint(i), uid: uint32(i), home: fmt.Sprintf("/home/%d", i)}
				}
				release := make(chan struct{})
				defer func() { close(release); synctest.Wait() }()
				for read := range tc.reads {
					counts := make([]int, len(tc.categories))
					var wg sync.WaitGroup
					for i, cat := range tc.categories {
						wg.Go(func() {
							ctx, cancel := context.WithTimeout(context.Background(), categoryBudget)
							defer cancel()
							seen := map[string]int{}
							readAccountResults(ctx, c, cat, accounts, func(a passwdEntry) int {
								c.accountMu.Lock()
								assert.LessOrEqual(t, c.accountCount, maxAccountWorkers)
								assert.LessOrEqual(t, c.accountInFlight[cat], maxConcurrentAccounts)
								c.accountMu.Unlock()
								if int(a.uid) < tc.hung {
									<-release
								} else {
									// Keep healthy reads overlapping while lanes enter.
									time.Sleep(time.Millisecond)
								}
								return 1
							}, func(a passwdEntry, value int, reason string) {
								seen[a.name]++
								if int(a.uid) < tc.hung {
									assert.Equal(t, reasonTimeout, reason)
								} else if reason == reasonTimeout {
									counts[i]++
								} else {
									assert.Empty(t, reason)
									assert.Equal(t, 1, value)
								}
							})
							assert.Len(t, seen, len(accounts))
							for _, a := range accounts {
								assert.Equal(t, 1, seen[a.name], a.name)
							}
						})
					}
					wg.Wait()
					synctest.Wait()
					t.Logf("read %d healthy timeouts: %v", read+1, counts)
					for _, count := range counts {
						assert.Zero(t, count, "read %d", read+1)
					}
					c.accountMu.Lock()
					assert.Equal(t, maxAccountWorkers, c.accountCount)
					for _, count := range c.accountInFlight {
						assert.LessOrEqual(t, count, maxConcurrentAccounts)
					}
					c.accountMu.Unlock()
				}
			})
		})
	}
}

func TestAccountApplyPanicDoesNotBlockLanes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newCollector(collectorOptions{budget: categoryBudget})
		accounts := make([]passwdEntry, 200)
		for i := range accounts {
			accounts[i].name = fmt.Sprint(i)
		}
		// A lane left blocked on its result send would outlive the bubble, and
		// synctest.Test fails on blocked goroutines when the bubble ends; a
		// process-wide goroutine count would also see other tests' goroutines.
		for range 5 {
			require.Panics(t, func() {
				readAccountResults(context.Background(), c, catKeys, accounts, func(passwdEntry) int { return 1 }, func(passwdEntry, int, string) { panic("apply") })
			})
			synctest.Wait()
		}
	})
}

func TestAccountCursorReturnsEachAccountExactlyOnce(t *testing.T) {
	for _, saturated := range []bool{false, true} {
		t.Run(fmt.Sprint(saturated), func(t *testing.T) {
			c := newCollector(collectorOptions{budget: categoryBudget})
			if saturated {
				c.accountInFlight[catKeys] = maxConcurrentAccounts
			}
			accounts := make([]passwdEntry, maxAccounts)
			for i := range accounts {
				accounts[i].name = fmt.Sprint(i)
			}
			seen := map[string]int{}
			readAccountResults(context.Background(), c, catKeys, accounts, func(a passwdEntry) string { runtime.Gosched(); return a.name }, func(a passwdEntry, value, reason string) {
				seen[a.name]++
				if saturated {
					assert.Equal(t, reasonTimeout, reason)
				} else {
					assert.Empty(t, reason)
					assert.Equal(t, a.name, value)
				}
			})
			require.Len(t, seen, len(accounts))
			for _, a := range accounts {
				assert.Equal(t, 1, seen[a.name], a.name)
			}
		})
	}
}
