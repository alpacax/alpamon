package updater

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	// minConfirmWindow is the least time a new process gets to confirm its
	// health, even when it starts after the recorded deadline.
	minConfirmWindow = 30 * time.Second
	statusRetryDelay = 10 * time.Second
	reportAttempts   = 5
	reportRetryDelay = 30 * time.Second
	rollbackTimeout  = 10 * time.Minute
)

// ResumeDeps is what finishing an in-flight upgrade needs from the agent.
type ResumeDeps struct {
	// Running is the version of this process.
	Running string
	// Authenticated is closed once the console connection has carried
	// traffic, the "reconnected" health signal.
	Authenticated <-chan struct{}
	// PostStatus reports status to the console; nil error is success.
	PostStatus func() error
	// Poster sends the upgrade report.
	Poster Poster
	// ServiceManager restarts the agent from outside and disarms the guard.
	ServiceManager ServiceManager
	// RequestRestart restarts the agent in process, used only when the
	// service manager cannot.
	RequestRestart func()

	runCommand commandRunner // test seam; nil means runCombined
}

// ResumePending finishes an upgrade the previous process left in flight. It
// reports whether one was found; the work runs in the background until ctx
// ends, and done is closed when it finishes.
//
// The version this process runs decides what the marker means: the target
// version must confirm its health before the deadline or roll back; the
// previous version means a rollback already happened and only needs
// reporting.
func ResumePending(ctx context.Context, d ResumeDeps) (found bool, done <-chan struct{}) {
	finished := make(chan struct{})
	if !stateDirSecureFn() {
		log.Error().Msg("Not resuming a pinned upgrade: the data directory could not be secured.")
		close(finished)
		return false, finished
	}
	p, err := LoadPending()
	if err != nil {
		log.Warn().Err(err).Str("path", MarkerPath()).Msg("Unreadable upgrade marker; removing it.")
		_ = ClearPending()
	}
	if p == nil {
		close(finished)
		return false, finished
	}
	if d.runCommand == nil {
		d.runCommand = runCombined
	}

	go func() {
		defer close(finished)
		switch {
		case versionsEqual(d.Running, p.ToVersion):
			confirmHealth(ctx, p, d)
		case versionsEqual(d.Running, p.FromVersion):
			finishRollback(ctx, p, d)
		default:
			finishUnexpected(ctx, p, d)
		}
	}()
	return true, finished
}

// confirmHealth waits for the three health signals: a reconnect, a
// successful status report, and this process running the target version
// (the branch that called it). It rolls back if the deadline passes first.
func confirmHealth(ctx context.Context, p *PendingUpgrade, d ResumeDeps) {
	window := max(time.Until(p.Deadline), minConfirmWindow)
	log.Info().Str("attempt_id", p.AttemptID).Str("to", p.ToVersion).Dur("window", window).
		Msg("Confirming the health of the upgraded agent.")
	timer := time.NewTimer(window)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return
	case <-timer.C:
		rollback(ctx, p, d, "the upgraded agent did not reconnect to the console before the deadline")
		return
	case <-d.Authenticated:
	}

	for {
		err := d.PostStatus()
		if err == nil {
			break
		}
		log.Warn().Err(err).Msg("Upgraded agent could not report status yet; retrying.")
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			rollback(ctx, p, d, fmt.Sprintf("the upgraded agent could not report status before the deadline: %v", err))
			return
		case <-time.After(statusRetryDelay):
		}
	}

	// Guard first: stopping its timer, or waiting out a guard that already
	// started. One that ran has restored the previous version and will
	// restart into it; the marker stays for that process to report.
	switch d.ServiceManager.DisarmGuard(p.GuardUnit) {
	case GuardRestored:
		log.Warn().Msg("The upgrade guard ran before the upgrade was confirmed; leaving the outcome to the restored version.")
		return
	case GuardRunning:
		log.Warn().Msg("The upgrade guard is still running; the next start repeats the check.")
		return
	case GuardFailed:
		// Its restore failed, so this version is still the one in place and
		// has just proven healthy.
		log.Warn().Msg("The upgrade guard ran but could not restore; confirming this version.")
	}
	if err := ClearPending(); err != nil {
		log.Error().Err(err).Msg("Failed to clear the upgrade marker; the next start repeats the check.")
		return
	}
	removeRollbackCopy(p)
	log.Info().Str("attempt_id", p.AttemptID).Str("version", p.ToVersion).Msg("Upgrade confirmed healthy.")
	sendReportWithRetry(ctx, d.Poster, Report{
		AttemptID:   p.AttemptID,
		FromVersion: p.FromVersion,
		ToVersion:   p.ToVersion,
		Outcome:     OutcomeSucceeded,
		Detail:      p.Note,
	})
}

// rollback restores the previous version and restarts into it. The marker
// stays, now carrying the reason, so the restored process reports it. On any
// failure the marker is left as it was for the guard to act on.
func rollback(ctx context.Context, p *PendingUpgrade, d ResumeDeps, reason string) {
	log.Error().Str("attempt_id", p.AttemptID).Str("reason", reason).Msg("Upgrade health check failed; rolling back.")

	current, err := LoadPending()
	if err != nil || current == nil {
		log.Warn().Err(err).Msg("Upgrade marker is gone; not rolling back.")
		return
	}

	switch p.Method {
	case MethodBinary:
		err = restoreBinary(p.RollbackPath, p.BinaryPath)
	case MethodPackage:
		// Stand the guard down while this reinstall runs, so the two never
		// drive the package manager at once; it is re-armed if this fails.
		switch d.ServiceManager.DisarmGuard(p.GuardUnit) {
		case GuardRestored:
			log.Warn().Msg("The upgrade guard already rolled back; nothing left to do here.")
			return
		case GuardRunning:
			log.Warn().Msg("The upgrade guard is still running; not starting a second reinstall.")
			return
		}
		var argv []string
		if argv, err = PackageRollbackCommand(p.PackageManager, p.PreviousPackageVersion, p.ToVersion); err == nil {
			rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
			var out []byte
			out, err = d.runCommand(rctx, argv[0], argv[1:]...)
			cancel()
			if err != nil {
				err = fmt.Errorf("%w: %s", err, out)
			}
		}
	default:
		err = fmt.Errorf("unknown upgrade method %q", p.Method)
	}
	if err != nil {
		p.RollbackAttempts++
		if p.RollbackAttempts >= maxRollbackAttempts || time.Now().After(p.Deadline.Add(staleMarkerAge)) {
			giveUpRollback(ctx, p, d, err)
			return
		}
		log.Error().Err(err).Int("attempt", p.RollbackAttempts).Msg("Rollback failed; leaving the marker for the upgrade guard.")
		if werr := WritePending(p); werr != nil {
			log.Error().Err(werr).Msg("Failed to record the rollback attempt.")
		}
		if p.Method == MethodPackage {
			aerr := armGuard(p, d.ServiceManager, 0, time.Now())
			if aerr != nil || p.GuardUnit == "" {
				// No guard: restart instead, so the next start, still the
				// failing version past its deadline, retries this rollback.
				log.Error().Err(aerr).Msg("No upgrade guard is armed; restarting to retry the rollback.")
				p.GuardUnit = ""
				if werr := WritePending(p); werr != nil {
					log.Error().Err(werr).Msg("Failed to update the upgrade marker.")
				}
				restart(d)
			}
		}
		return
	}

	p.RollbackClass = ClassHealthCheckFailed
	p.RollbackDetail = truncate(reason, 4*maxMarkerTextLen)
	if err := WritePending(p); err != nil {
		log.Warn().Err(err).Msg("Failed to record the rollback reason in the upgrade marker.")
	}
	restart(d)
}

// maxRollbackAttempts bounds the in-process rollback retries.
const maxRollbackAttempts = 3

// giveUpRollback ends an attempt whose rollback keeps failing: it reports the
// failure and removes the marker, so the agent stops retrying and stays on
// the version it runs.
func giveUpRollback(ctx context.Context, p *PendingUpgrade, d ResumeDeps, err error) {
	log.Error().Err(err).Int("attempts", p.RollbackAttempts).Msg("Giving up on rolling back the upgrade; staying on this version.")
	if !clearForReport(p, d, false) {
		return
	}
	sendReportWithRetry(ctx, d.Poster, Report{
		AttemptID:   p.AttemptID,
		FromVersion: p.FromVersion,
		ToVersion:   p.ToVersion,
		Outcome:     OutcomeFailed,
		ErrorClass:  ClassHealthCheckFailed,
		Detail:      truncate(fmt.Sprintf("health check failed and the rollback failed %d times: %v", p.RollbackAttempts, err), 4*maxMarkerTextLen),
	})
}

func restart(d ResumeDeps) {
	err := d.ServiceManager.ScheduleRestart(RestartDelay)
	if err == nil {
		return
	}
	log.Warn().Err(err).Msg("Service manager could not schedule the restart; restarting in process.")
	d.RequestRestart()
}

// finishRollback runs in the restored previous version and reports the
// rollback, whether this process's predecessor or the guard performed it.
func finishRollback(ctx context.Context, p *PendingUpgrade, d ResumeDeps) {
	if !clearForReport(p, d, true) {
		return
	}

	class, detail := p.RollbackClass, p.RollbackDetail
	if class == "" {
		class = ClassHealthCheckFailed
		detail = "the upgraded agent did not confirm its health before the deadline, or never started; the previous version was restored"
	}
	if p.Note != "" {
		detail = p.Note + "; " + detail
	}
	log.Warn().Str("attempt_id", p.AttemptID).Str("from", p.FromVersion).Str("to", p.ToVersion).
		Msg("Upgrade was rolled back; running the previous version.")
	sendReportWithRetry(ctx, d.Poster, Report{
		AttemptID:   p.AttemptID,
		FromVersion: p.FromVersion,
		ToVersion:   p.ToVersion,
		Outcome:     OutcomeRolledBack,
		ErrorClass:  class,
		Detail:      detail,
	})
}

// finishUnexpected handles a process that is neither the version replaced
// nor the target, such as after an operator installed another build.
func finishUnexpected(ctx context.Context, p *PendingUpgrade, d ResumeDeps) {
	if !clearForReport(p, d, false) {
		return
	}
	sendReportWithRetry(ctx, d.Poster, Report{
		AttemptID:   p.AttemptID,
		FromVersion: p.FromVersion,
		ToVersion:   p.ToVersion,
		Outcome:     OutcomeFailed,
		ErrorClass:  ClassUnknown,
		Detail:      fmt.Sprintf("agent started as version %s, neither the replaced nor the target version", d.Running),
	})
}

// clearForReport removes the marker, then the guard and the rollback copy.
// When the marker cannot be removed it leaves all three and reports false,
// so nothing is reported until a later start can finish the job.
//
// Guard first, so nothing it may still need is removed under it. A guard that
// is still running always defers the cleanup; one that restored does so
// unless this process is the version it restored (restored is true).
func clearForReport(p *PendingUpgrade, d ResumeDeps, restored bool) bool {
	switch d.ServiceManager.DisarmGuard(p.GuardUnit) {
	case GuardRunning:
		log.Warn().Msg("The upgrade guard is still running; leaving the attempt for the next start.")
		return false
	case GuardRestored:
		if !restored {
			log.Warn().Msg("The upgrade guard has restored the previous version; leaving the attempt to it.")
			return false
		}
	}
	if err := ClearPending(); err != nil {
		log.Error().Err(err).Msg("Failed to clear the upgrade marker; leaving the attempt for the next start.")
		return false
	}
	removeRollbackCopy(p)
	return true
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func sendReportWithRetry(ctx context.Context, p Poster, r Report) {
	for attempt := 1; ; attempt++ {
		if SendReport(p, r) || attempt >= reportAttempts {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(reportRetryDelay):
		}
	}
}
