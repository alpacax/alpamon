package runner

import (
	"context"
	"encoding/binary"
)

const terminalInputTokenSize = 8

// enqueueInput tags governed input with the fence version at receipt. This
// metadata stays inside wsToPty and is removed before writing to the terminal.
func (pc *PtyClient) enqueueInput(ctx context.Context, msg []byte) bool {
	token, allowed := pc.workSession.inputToken()
	if !allowed {
		return true
	}
	if pc.workSession != nil {
		queued := make([]byte, terminalInputTokenSize+len(msg))
		binary.BigEndian.PutUint64(queued, token)
		copy(queued[terminalInputTokenSize:], msg)
		msg = queued
	}
	select {
	case pc.wsToPty <- msg:
		return true
	case <-ctx.Done():
		return false
	}
}

func (pc *PtyClient) writeQueuedInput(msg []byte) error {
	if pc.workSession != nil {
		if len(msg) < terminalInputTokenSize || !pc.workSession.inputAllowedAt(binary.BigEndian.Uint64(msg)) {
			return nil
		}
		msg = msg[terminalInputTokenSize:]
	}
	return pc.writeInput(msg)
}

func (pc *PtyClient) writeToPty(ctx context.Context, cancel context.CancelFunc) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-pc.wsToPty:
			if err := pc.writeQueuedInput(msg); err != nil {
				cancel()
				return
			}
		}
	}
}
