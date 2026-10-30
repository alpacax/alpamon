package runner

import (
	"container/list"
	"context"
	"sync"
	"time"

	"github.com/alpacax/alpamon/v2/internal/commandcancel"
	"github.com/rs/zerolog/log"
)

const (
	cancelledCommandLimit = 10000
	cancelledCommandTTL   = time.Hour
)

type recentCommand struct {
	id        string
	cancelled bool
	expires   time.Time
}

type commandCancellations struct {
	mu     sync.Mutex
	active map[string]map[*commandcancel.State]struct{}
	recent map[string]*list.Element
	order  list.List
}

func (c *commandCancellations) prune(now time.Time) {
	for e := c.order.Front(); e != nil; e = c.order.Front() {
		entry := e.Value.(recentCommand)
		if entry.expires.After(now) && c.order.Len() <= cancelledCommandLimit {
			break
		}
		delete(c.recent, entry.id)
		c.order.Remove(e)
	}
}

func (c *commandCancellations) remember(id string, cancelled bool, now time.Time) {
	if c.recent == nil {
		c.recent = make(map[string]*list.Element)
	}
	if e := c.recent[id]; e != nil {
		c.order.Remove(e)
	}
	c.recent[id] = c.order.PushBack(recentCommand{id: id, cancelled: cancelled, expires: now.Add(cancelledCommandTTL)})
	c.prune(now)
}

func (c *commandCancellations) register(parent context.Context, id string) (context.Context, *commandcancel.State) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	c.prune(now)
	ctx, state := commandcancel.NewContext(parent)
	if c.active == nil {
		c.active = make(map[string]map[*commandcancel.State]struct{})
	}
	if c.active[id] == nil {
		c.active[id] = make(map[*commandcancel.State]struct{})
	}
	c.active[id][state] = struct{}{}
	if e := c.recent[id]; e != nil && e.Value.(recentCommand).cancelled {
		state.Cancel()
	}
	return ctx, state
}

func (c *commandCancellations) wasCancelled(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.prune(time.Now())
	e := c.recent[id]
	return e != nil && e.Value.(recentCommand).cancelled
}

func (c *commandCancellations) cancel(id string) {
	if id == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	c.prune(now)
	if len(c.active[id]) == 0 {
		log.Debug().Str("command_id", id).Msg("Cancel received for an unknown or finished command")
		if e := c.recent[id]; e != nil {
			return
		}
		// No immediate report or process action; retain an out-of-order cancellation.
		c.remember(id, true, now)
		return
	}
	for state := range c.active[id] {
		state.Cancel()
	}
	c.remember(id, true, now)
}

func (c *commandCancellations) finish(id string, state *commandcancel.State) (bool, []int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cancelled, survivors := state.Finish()
	delete(c.active[id], state)
	if len(c.active[id]) == 0 {
		delete(c.active, id)
	}
	if id != "" {
		c.remember(id, cancelled, time.Now())
	}
	return cancelled, survivors
}
