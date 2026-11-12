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

const unitShowProperties = "Id,User,LoadState,DynamicUser,Transient,ActiveState,Triggers,Accept"
const unitBatchSize = 128

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

func (l *linuxAccountLocker) unitProperties(ctx context.Context, names []string) (map[string]map[string]string, error) {
	properties := make(map[string]map[string]string)
	var errs []error
	for chunk := range slices.Chunk(names, unitBatchSize) {
		args := []string{"show", "--property=" + unitShowProperties, "--"}
		for _, name := range chunk {
			if strings.HasSuffix(name, "@.service") {
				name = strings.TrimSuffix(name, "@.service") + "@alpamon-lock-probe.service"
			}
			args = append(args, name)
		}
		output, err := l.run(ctx, l.systemctl, args...)
		if err != nil {
			errs = append(errs, fmt.Errorf("unit_unresolved: %s: %w", chunk[0], err))
			continue
		}
		var blocks []map[string]string
		block := make(map[string]string)
		for line := range strings.SplitSeq(output, "\n") {
			if strings.TrimSpace(line) == "" {
				if len(block) > 0 {
					blocks = append(blocks, block)
					block = make(map[string]string)
				}
				continue
			}
			if key, value, ok := strings.Cut(line, "="); ok {
				block[key] = value
			}
		}
		if len(block) > 0 {
			blocks = append(blocks, block)
		}
		if len(blocks) != len(chunk) {
			errs = append(errs, fmt.Errorf("unit_unresolved: %s", chunk[0]))
			continue
		}
		for i, name := range chunk {
			properties[name] = blocks[i]
		}
	}
	return properties, errors.Join(errs...)
}

func (l *linuxAccountLocker) accountUnits(ctx context.Context, name string, uid uint64) ([]accountUnit, error) {
	var names []string
	seenNames := make(map[string]bool)
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
		if len(fields) > 0 && !seenNames[fields[0]] {
			seenNames[fields[0]] = true
			names = append(names, fields[0])
		}
	}
	output, err = l.run(ctx, l.systemctl, "list-unit-files", "--type=service", "--no-legend")
	if err != nil {
		errs = append(errs, err)
	}
	for line := range strings.SplitSeq(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && validService(fields[0]) && !strings.HasSuffix(fields[0], "@.service") && !seenNames[fields[0]] {
			seenNames[fields[0]] = true
			names = append(names, fields[0])
		}
	}
	properties, err := l.unitProperties(ctx, names)
	errs = append(errs, err)
	var sockets []string
	for _, unit := range names {
		if strings.HasSuffix(unit, ".socket") && properties[unit]["Accept"] == "yes" {
			sockets = append(sockets, unit)
		}
	}
	socketServices, err := l.socketServices(ctx, sockets)
	errs = append(errs, err)
	var services []string
	templates := make(map[string]bool)
	serviceTriggers := make(map[string][]string)
	for _, unit := range names {
		props, resolved := properties[unit]
		if !resolved {
			continue
		}
		if validService(unit) && !strings.HasSuffix(unit, "@.service") {
			services = append(services, unit)
			continue
		}
		if strings.HasSuffix(unit, "@.service") {
			continue
		}
		triggers := props["Triggers"]
		if strings.HasSuffix(unit, ".socket") && props["Accept"] == "yes" {
			var ok bool
			triggers, ok = socketServices[unit]
			if !ok {
				continue
			}
			if triggers == "" {
				triggers = strings.TrimSuffix(unit, ".socket") + "@.service"
			}
			templates[triggers] = strings.HasSuffix(triggers, "@.service")
		}
		for _, service := range strings.Fields(triggers) {
			if validService(service) && (!strings.HasSuffix(service, "@.service") || templates[service]) {
				services = append(services, service)
				serviceTriggers[service] = append(serviceTriggers[service], unit)
			}
		}
	}
	var probes []string
	seen := make(map[string]bool)
	for _, service := range services {
		if seen[service] {
			continue
		}
		seen[service] = true
		// Reuse the first pass, including a failed chunk; probe only newly named services.
		if !seenNames[service] {
			probes = append(probes, service)
		}
	}
	extra, err := l.unitProperties(ctx, probes)
	errs = append(errs, err)
	for service, props := range extra {
		properties[service] = props
	}
	var units []accountUnit
	clear(seen)
	for _, service := range services {
		if seen[service] {
			continue
		}
		seen[service] = true
		props, resolved := properties[service]
		if !resolved {
			continue
		}
		owner := props["User"]
		if owner == "" && props["LoadState"] != "loaded" && props["LoadState"] != "masked" {
			errs = append(errs, fmt.Errorf("unit_unresolved: %s", service))
			continue
		}
		matches := owner == name || owner == strconv.FormatUint(uid, 10)
		if owner != "" && owner != "root" && !matches {
			if ownerUID, err := strconv.ParseUint(owner, 10, 32); err == nil {
				matches = ownerUID == uid
			} else {
				account, err := l.handler.lookupUser(owner)
				if err != nil || account == nil {
					if props["DynamicUser"] == "yes" {
						continue
					}
					errs = append(errs, fmt.Errorf("unit_unresolved: %s", service))
					continue
				}
				matches = account.Uid == strconv.FormatUint(uid, 10)
			}
		}
		if !matches {
			continue
		}
		active := props["ActiveState"]
		unit := accountUnit{name: service, transient: props["Transient"] == "yes", running: active != "inactive" && active != "failed" && active != "", acceptTemplate: templates[service]}
		for _, trigger := range serviceTriggers[service] {
			if properties[trigger]["ActiveState"] == "active" {
				unit.triggers = append(unit.triggers, trigger)
			}
		}
		units = append(units, unit)
	}
	return units, errors.Join(errs...)
}

func (l *linuxAccountLocker) installDropIns(ctx context.Context, name string, units []accountUnit, states map[string]accountLockState, state *accountLockState) error {
	var errs []error
	written := make(map[string]bool)
	var paths []string
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
					if other != name && slices.Contains(saved.DropIns, path) {
						errs = append(errs, fmt.Errorf("unit_lock_conflict: %s", unit.name))
						conflict = true
					}
				}
			}
			if conflict {
				continue
			}
			paths = append(paths, path)
			if !slices.Contains(state.DropIns, path) {
				state.DropIns = append(state.DropIns, path)
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(append(errs, err)...)
	}
	states[name] = *state
	if err := l.store.save(states); err != nil {
		return errors.Join(append(errs, fmt.Errorf("lock_state_failed: %w", err))...)
	}
	content := "[Unit]\nConditionPathExists=!" + filepath.Join(l.files.markerDir, name) + "\n"
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(errs, err)...)
		}
		if err := l.files.write(path, content, 0644, 0755); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, err))
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

// Service= is not a socket D-Bus property. Batch the fragments and drop-ins,
// preserving systemd's merge order within each socket's configuration.
func (l *linuxAccountLocker) socketServices(ctx context.Context, names []string) (map[string]string, error) {
	result := make(map[string]string)
	var errs []error
	for chunk := range slices.Chunk(names, unitBatchSize) {
		output, err := l.run(ctx, l.systemctl, append([]string{"cat", "--"}, chunk...)...)
		if err != nil {
			errs = append(errs, fmt.Errorf("unit_unresolved: %s: %w", chunk[0], err))
			continue
		}
		var bodies []string
		for line := range strings.SplitSeq(output, "\n") {
			// Each fragment begins a unit block; inherited and instance drop-ins
			// remain part of that block even when their filenames name another unit.
			if strings.HasPrefix(line, "# /") && strings.HasSuffix(line, ".socket") {
				bodies = append(bodies, "")
			}
			if len(bodies) > 0 {
				bodies[len(bodies)-1] += line + "\n"
			}
		}
		if len(bodies) != len(chunk) {
			errs = append(errs, fmt.Errorf("unit_unresolved: %s", chunk[0]))
			continue
		}
		for i, name := range chunk {
			body := bodies[i]
			service, err := socketService(body)
			if err != nil {
				errs = append(errs, fmt.Errorf("unit_unresolved: %s: %w", name, err))
				continue
			}
			result[name] = service
		}
	}
	return result, errors.Join(errs...)
}

func socketService(output string) (string, error) {
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

func (l *linuxAccountLocker) stoppedTriggers(ctx context.Context, triggers []string) []string {
	var left []string
	for _, unit := range triggers {
		result, err := l.unitProperty(ctx, unit, "Result")
		if err != nil || result == "trigger-limit-hit" {
			left = append(left, unit)
		}
	}
	return left
}
