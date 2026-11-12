package user

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

type accountUnit struct {
	name           string
	transient      bool
	running        bool
	acceptTemplate bool
	triggers       []string
}

func (l *linuxAccountLocker) unitProperty(ctx context.Context, unit, property string) (string, error) {
	// systemd cannot show an uninstantiated template. Loading an inert instance
	// resolves its properties without starting it.
	if strings.HasSuffix(unit, "@.service") {
		unit = strings.TrimSuffix(unit, "@.service") + "@alpamon-lock-probe.service"
	}
	value, err := l.run(ctx, l.systemctl, "show", "--property="+property, "--value", "--", unit)
	return strings.TrimSpace(value), err
}

func (l *linuxAccountLocker) accountUnits(ctx context.Context, name string, uid uint64) ([]accountUnit, error) {
	var names []string
	var errs []error
	output, err := l.run(ctx, l.systemctl, "list-units", "--all", "--type=service,timer,socket,path", "--no-legend", "--no-pager", "--plain")
	if err != nil {
		errs = append(errs, err)
	}
	for line := range strings.SplitSeq(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 1 && fields[1] == "not-found" {
			continue
		}
		if len(fields) > 0 && !slices.Contains(names, fields[0]) {
			names = append(names, fields[0])
		}
	}
	output, err = l.run(ctx, l.systemctl, "list-unit-files", "--type=service", "--no-legend")
	if err != nil {
		errs = append(errs, err)
	}
	for line := range strings.SplitSeq(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && validService(fields[0]) && !strings.HasSuffix(fields[0], "@.service") && !slices.Contains(names, fields[0]) {
			names = append(names, fields[0])
		}
	}
	var services []string
	templates := make(map[string]bool)
	serviceTriggers := make(map[string][]string)
	for _, unit := range names {
		if validService(unit) && !strings.HasSuffix(unit, "@.service") {
			services = append(services, unit)
			continue
		}
		if strings.HasSuffix(unit, "@.service") {
			continue
		}
		triggers, err := l.unitProperty(ctx, unit, "Triggers")
		if err != nil {
			errs = append(errs, fmt.Errorf("unit_unresolved: %s: %w", unit, err))
			continue
		}
		if strings.HasSuffix(unit, ".socket") {
			accept, err := l.unitProperty(ctx, unit, "Accept")
			if err != nil {
				errs = append(errs, fmt.Errorf("unit_unresolved: %s: %w", unit, err))
				continue
			}
			if accept == "yes" {
				triggers, err = l.socketService(ctx, unit)
				if err != nil {
					errs = append(errs, fmt.Errorf("unit_unresolved: %s: %w", unit, err))
					continue
				}
				if triggers == "" {
					triggers = strings.TrimSuffix(unit, ".socket") + "@.service"
				}
				templates[triggers] = strings.HasSuffix(triggers, "@.service")
			}
		}
		for _, service := range strings.Fields(triggers) {
			if validService(service) && (!strings.HasSuffix(service, "@.service") || templates[service]) {
				services = append(services, service)
				serviceTriggers[service] = append(serviceTriggers[service], unit)
			}
		}
	}
	var units []accountUnit
	seen := make(map[string]bool)
	for _, service := range services {
		if seen[service] {
			continue
		}
		seen[service] = true
		owner, err := l.unitProperty(ctx, service, "User")
		if err != nil {
			errs = append(errs, fmt.Errorf("unit_unresolved: %s: %w", service, err))
			continue
		}
		if owner == "" {
			loadState, err := l.unitProperty(ctx, service, "LoadState")
			if err != nil || (loadState != "loaded" && loadState != "masked") {
				errs = append(errs, fmt.Errorf("unit_unresolved: %s", service))
				continue
			}
		}
		matches := owner == name || owner == strconv.FormatUint(uid, 10)
		if owner != "" && owner != "root" && !matches {
			if ownerUID, err := strconv.ParseUint(owner, 10, 32); err == nil {
				matches = ownerUID == uid
			} else {
				account, err := l.handler.lookupUser(owner)
				if err != nil || account == nil {
					errs = append(errs, fmt.Errorf("unit_unresolved: %s", service))
					continue
				}
				matches = account.Uid == strconv.FormatUint(uid, 10)
			}
		}
		if !matches {
			continue
		}
		transient, err := l.unitProperty(ctx, service, "Transient")
		if err != nil {
			errs = append(errs, fmt.Errorf("unit_unresolved: %s: %w", service, err))
			continue
		}
		active, err := l.unitProperty(ctx, service, "ActiveState")
		if err != nil {
			errs = append(errs, fmt.Errorf("unit_unresolved: %s: %w", service, err))
			continue
		}
		unit := accountUnit{name: service, transient: transient == "yes", running: active != "inactive" && active != "failed" && active != "", acceptTemplate: templates[service]}
		for _, trigger := range serviceTriggers[service] {
			active, err := l.unitProperty(ctx, trigger, "ActiveState")
			if err != nil {
				errs = append(errs, fmt.Errorf("unit_unresolved: %s: %w", trigger, err))
				continue
			}
			if active == "active" {
				unit.triggers = append(unit.triggers, trigger)
			}
		}
		units = append(units, unit)
	}
	return units, errors.Join(errs...)
}

func (l *linuxAccountLocker) installDropIns(name string, units []accountUnit, states map[string]accountLockState, state *accountLockState) error {
	var errs []error
	written := make(map[string]bool)
	for _, unit := range units {
		if unit.transient {
			continue
		}
		service := unit.name
		for _, root := range l.files.unitDirs {
			path := filepath.Join(root, service+".d", lockDropInName)
			if written[path] {
				continue
			}
			written[path] = true
			conflict := false
			if unit.acceptTemplate {
				for other, saved := range states {
					if other != name && slices.Contains(lockDropInPaths(saved.DropIns), path) {
						errs = append(errs, fmt.Errorf("unit_lock_conflict: %s", unit.name))
						conflict = true
					}
				}
			}
			if conflict {
				continue
			}
			if !slices.Contains(state.DropIns, path) {
				state.DropIns = append(state.DropIns, path)
			}
			states[name] = *state
			if err := l.store.save(states); err != nil {
				errs = append(errs, fmt.Errorf("lock_state_failed: %w", err))
				continue
			}
			content := "[Unit]\nConditionPathExists=!" + filepath.Join(l.files.markerDir, name) + "\n"
			if err := l.files.write(path, content, 0644, 0755); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", path, err))
			}
		}
	}
	return errors.Join(errs...)
}

func (l *linuxAccountLocker) stopServices(ctx context.Context, name string, uid uint64, units []accountUnit) error {
	var running []string
	var persistent []string
	for _, unit := range units {
		if !unit.running {
			continue
		}
		running = append(running, unit.name)
		if !unit.transient {
			persistent = append(persistent, unit.name)
		}
	}
	if len(running) == 0 {
		return nil
	}
	err := l.runForAccount(ctx, name, uid, l.systemctl, append([]string{"stop", "--no-block", "--job-mode=ignore-dependencies", "--"}, running...)...)
	if err == nil {
		return nil
	}
	// A disappearing transient unit fails the batch even when every persistent
	// stop was accepted. Verify those jobs before discounting the batch error.
	if len(persistent) == len(running) {
		return err
	}
	var errs []error
	for _, unit := range persistent {
		active, activeErr := l.unitProperty(ctx, unit, "ActiveState")
		if activeErr != nil {
			errs = append(errs, errors.Join(err, activeErr))
			continue
		}
		if active == "inactive" || active == "failed" || active == "deactivating" {
			continue
		}
		job, jobErr := l.unitProperty(ctx, unit, "Job")
		if jobErr != nil || job == "" {
			errs = append(errs, errors.Join(err, jobErr))
		}
	}
	return errors.Join(errs...)
}

// Service= is not a socket D-Bus property. Read the fragment and drop-ins in
// systemd's merge order, retaining the last assignment in the Socket section.
func (l *linuxAccountLocker) socketService(ctx context.Context, unit string) (string, error) {
	output, err := l.run(ctx, l.systemctl, "cat", "--", unit)
	if err != nil {
		return "", err
	}
	section, service, continued := "", "", ""
	for line := range strings.SplitSeq(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		line = continued + line
		if strings.HasSuffix(line, "\\") {
			continued = strings.TrimSuffix(line, "\\") + " "
			continue
		}
		continued = ""
		if strings.HasPrefix(line, "[") {
			section = line
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if found && section == "[Socket]" && strings.TrimSpace(key) == "Service" {
			service = strings.Trim(strings.TrimSpace(value), "\"'")
			if service != "" && (!validService(service) || strings.ContainsAny(service, "%\\")) {
				return "", fmt.Errorf("invalid socket service")
			}
		}
	}
	return service, nil
}

func (l *linuxAccountLocker) restoreTriggers(ctx context.Context, triggers []string) []string {
	var left []string
	for _, unit := range triggers {
		result, err := l.unitProperty(ctx, unit, "Result")
		if err != nil {
			left = append(left, unit)
			continue
		}
		if result != "trigger-limit-hit" {
			continue
		}
		if _, err := l.run(ctx, l.systemctl, "reset-failed", "--", unit); err != nil {
			left = append(left, unit)
			continue
		}
		if _, err := l.run(ctx, l.systemctl, "start", "--", unit); err != nil {
			left = append(left, unit)
			continue
		}
		active, err := l.unitProperty(ctx, unit, "ActiveState")
		if err != nil || active != "active" {
			left = append(left, unit)
		}
	}
	return left
}
