package runner

import "context"

func (r *WorkSessionRegistry) owned(id string) (commands, terminals []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.sessions[id]
	if s == nil {
		return nil, nil
	}
	work := s.owned()
	return work.Commands, work.Terminals
}

func TrackWorkSessionProcess(ctx context.Context, commandID string, pid int) {
	if b := workSessionFromContext(ctx); b != nil {
		b.registry.trackProcess(b.id, ownedKindCommand, commandID, pid)
	}
}
