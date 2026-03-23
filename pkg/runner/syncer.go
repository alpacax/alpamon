package runner

import (
	"encoding/json"
	"net/http"

	"github.com/alpacax/alpamon/pkg/scheduler"
	"github.com/alpacax/alpamon/pkg/utils"
	"github.com/rs/zerolog/log"
)

// Syncer encapsulates per-category sync logic.
type Syncer interface {
	Key() string
	Collect() (any, error)
	Def() commitDef
}

// syncable extends Syncer with sync execution capability.
type syncable interface {
	Syncer
	syncWith(session *scheduler.Session)
}

// syncers registers all 9 syncable data categories.
// server and firewall are handled separately.
var syncers = []syncable{
	&singleRowSyncer[SystemData]{key: "info", collect: getSystemData},
	&singleRowSyncer[OSData]{key: "os", collect: getOsData},
	&singleRowSyncer[TimeData]{key: "time", collect: getTimeData},
	&multiRowSyncer[UserData]{key: "users", collect: getUserData},
	&multiRowSyncer[GroupData]{key: "groups", collect: getGroupData},
	&multiRowSyncer[Interface]{key: "interfaces", collect: getNetworkInterfaces},
	&multiRowSyncer[Address]{key: "addresses", collect: getNetworkAddresses},
	&multiRowSyncer[Disk]{key: "disks", collect: getDisks},
	&multiRowSyncer[Partition]{key: "partitions", collect: getPartitions},
}

// singleRowSyncer handles categories with a single data row (info, os, time).
type singleRowSyncer[T ComparableData] struct {
	key     string
	collect func() (T, error)
}

func (s *singleRowSyncer[T]) Key() string { return s.key }

func (s *singleRowSyncer[T]) Collect() (any, error) { return s.collect() }

func (s *singleRowSyncer[T]) Def() commitDef { return commitDefs[s.key] }

func (s *singleRowSyncer[T]) syncWith(session *scheduler.Session) {
	current, err := s.collect()
	if err != nil {
		log.Debug().Err(err).Msgf("Failed to collect %s data.", s.key)
		return
	}

	entry := s.Def()
	resp, statusCode, err := session.Get(utils.JoinPath(entry.URL, entry.URLSuffix), 10)
	if err != nil {
		log.Error().Err(err).Msgf("HTTP %d: Failed to get data for %s.", statusCode, s.key)
		return
	}
	switch statusCode {
	case http.StatusOK:
		var remote T
		if err := json.Unmarshal(resp, &remote); err != nil {
			log.Error().Err(err).Msg("Failed to unmarshal remote data.")
			return
		}
		compareData(entry, current, remote)
	case http.StatusNotFound:
		compareData(entry, current, nil)
	default:
		log.Error().Msgf("Unexpected HTTP %d when syncing %s.", statusCode, s.key)
	}
}

// multiRowSyncer handles categories with multiple data rows (users, groups, etc.).
type multiRowSyncer[T ComparableData] struct {
	key     string
	collect func() ([]T, error)
}

func (s *multiRowSyncer[T]) Key() string { return s.key }

func (s *multiRowSyncer[T]) Collect() (any, error) { return s.collect() }

func (s *multiRowSyncer[T]) Def() commitDef { return commitDefs[s.key] }

func (s *multiRowSyncer[T]) syncWith(session *scheduler.Session) {
	current, err := s.collect()
	if err != nil {
		log.Debug().Err(err).Msgf("Failed to collect %s data.", s.key)
		return
	}

	entry := s.Def()
	resp, statusCode, err := session.Get(utils.JoinPath(entry.URL, entry.URLSuffix), 10)
	if err != nil {
		log.Error().Err(err).Msgf("HTTP %d: Failed to get data for %s.", statusCode, s.key)
		return
	}
	switch statusCode {
	case http.StatusOK:
		var remote []T
		if err := json.Unmarshal(resp, &remote); err != nil {
			log.Error().Err(err).Msg("Failed to unmarshal remote data.")
			return
		}
		compareListData(entry, current, remote)
	case http.StatusNotFound:
		compareListData(entry, current, nil)
	default:
		log.Error().Msgf("Unexpected HTTP %d when syncing %s.", statusCode, s.key)
	}
}

// syncerMap is a lookup map from key to syncable, built from syncers.
var syncerMap = func() map[string]syncable {
	m := make(map[string]syncable, len(syncers))
	for _, s := range syncers {
		key := s.Key()
		if _, exists := m[key]; exists {
			log.Fatal().Str("key", key).Msg("duplicate syncer key registered")
		}
		m[key] = s
	}
	return m
}()

// allSyncKeys returns all sync keys including server and firewall.
// server is first (patches version/load before data syncs), firewall is last (delegated to executor).
func allSyncKeys() []string {
	keys := make([]string, 0, len(syncers)+2)
	keys = append(keys, "server")
	for _, s := range syncers {
		keys = append(keys, s.Key())
	}
	keys = append(keys, "firewall")
	return keys
}

// assignToCommitData maps a syncer's collected data to the appropriate commitData field.
func assignToCommitData(data *commitData, key string, result any) {
	switch key {
	case "info":
		data.Info = result.(SystemData)
	case "os":
		data.OS = result.(OSData)
	case "time":
		data.Time = result.(TimeData)
	case "users":
		data.Users = result.([]UserData)
	case "groups":
		data.Groups = result.([]GroupData)
	case "interfaces":
		data.Interfaces = result.([]Interface)
	case "addresses":
		data.Addresses = result.([]Address)
	case "disks":
		data.Disks = result.([]Disk)
	case "partitions":
		data.Partitions = result.([]Partition)
	}
}
