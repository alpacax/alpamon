package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"

	"github.com/alpacax/alpamon/pkg/scheduler"
	"github.com/alpacax/alpamon/pkg/utils"
	"github.com/rs/zerolog/log"
)

// Syncer encapsulates per-category sync logic.
type Syncer interface {
	Key() string
	Collect() (any, error)
	Def() commitDef
	ComputeHash(data any) string
}

// syncable extends Syncer with sync execution using pre-collected data.
type syncable interface {
	Syncer
	// syncData syncs using pre-collected data from Collect().
	// The hash protocol collects data once in Step 1 for hashing
	// and reuses it here in Step 3 for syncing.
	// The hash is sent as X-Sync-Hash header on write requests
	// so the server can store it for future sync-check comparisons.
	syncData(session *scheduler.Session, data any, hash string)
}

// syncers registers all 9 syncable data categories.
// server and firewall are handled separately.
var syncers = []syncable{
	&singleRowSyncer[SystemData]{key: "info", collect: getSystemData},
	&singleRowSyncer[OSData]{key: "os", collect: getOsData},
	&singleRowSyncer[TimeData]{
		key:     "time",
		collect: getTimeData,
		hashTransform: func(td TimeData) any {
			return td.GetComparableData()
		},
	},
	&multiRowSyncer[UserData]{key: "users", collect: getUserData},
	&multiRowSyncer[GroupData]{key: "groups", collect: getGroupData},
	&multiRowSyncer[Interface]{key: "interfaces", collect: getNetworkInterfaces},
	&multiRowSyncer[Address]{key: "addresses", collect: getNetworkAddresses},
	&multiRowSyncer[Disk]{key: "disks", collect: getDisks},
	&multiRowSyncer[Partition]{key: "partitions", collect: getPartitions},
}

// singleRowSyncer handles categories with a single data row (info, os, time).
type singleRowSyncer[T ComparableData] struct {
	key           string
	collect       func() (T, error)
	hashTransform func(T) any
}

func (s *singleRowSyncer[T]) Key() string { return s.key }

func (s *singleRowSyncer[T]) Collect() (any, error) { return s.collect() }

func (s *singleRowSyncer[T]) Def() commitDef { return commitDefs[s.key] }

func (s *singleRowSyncer[T]) ComputeHash(data any) string {
	typed, ok := data.(T)
	if !ok {
		log.Debug().Str("key", s.key).Msg("Unexpected data type in ComputeHash, forcing sync.")
		return ""
	}
	if s.hashTransform != nil {
		return computeFingerprint(s.hashTransform(typed))
	}
	return computeFingerprint(typed)
}

func (s *singleRowSyncer[T]) syncData(session *scheduler.Session, data any, hash string) {
	current, ok := data.(T)
	if !ok {
		log.Error().Msgf("Invalid data type for %s, skipping sync.", s.key)
		return
	}
	entry := s.Def()
	resp, statusCode, err := session.Get(utils.JoinPath(entry.URL, entry.URLSuffix), 10)
	if err != nil {
		log.Error().Err(err).Msgf("Failed to get data for %s.", s.key)
		return
	}
	switch statusCode {
	case http.StatusOK:
		var remote T
		if err := json.Unmarshal(resp, &remote); err != nil {
			log.Error().Err(err).Msgf("Failed to unmarshal remote data for %s.", s.key)
			return
		}
		compareData(entry, current, remote, hash)
	case http.StatusNotFound:
		compareData(entry, current, nil, hash)
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

func (s *multiRowSyncer[T]) ComputeHash(data any) string {
	return computeFingerprint(data)
}

func (s *multiRowSyncer[T]) syncData(session *scheduler.Session, data any, hash string) {
	current, ok := data.([]T)
	if !ok {
		log.Error().Msgf("Invalid data type for %s, skipping sync.", s.key)
		return
	}
	entry := s.Def()
	resp, statusCode, err := session.Get(utils.JoinPath(entry.URL, entry.URLSuffix), 10)
	if err != nil {
		log.Error().Err(err).Msgf("Failed to get data for %s.", s.key)
		return
	}
	switch statusCode {
	case http.StatusOK:
		var remote []T
		if err := json.Unmarshal(resp, &remote); err != nil {
			log.Error().Err(err).Msgf("Failed to unmarshal remote data for %s.", s.key)
			return
		}
		compareListData(entry, current, remote, hash)
	case http.StatusNotFound:
		compareListData(entry, current, nil, hash)
	default:
		log.Error().Msgf("Unexpected HTTP %d when syncing %s.", statusCode, s.key)
	}
}

// syncSnapshot holds the result of Step 1: per-category collected data and their hashes.
type syncSnapshot struct {
	hashes map[string]string
	data   map[string]any
}

// collectSnapshot collects data and computes hashes for the given syncers.
// If keys is empty, all syncers are collected (full sync).
func collectSnapshot(keys []string) syncSnapshot {
	fullSync := len(keys) == 0
	snap := syncSnapshot{
		hashes: make(map[string]string, len(syncers)),
		data:   make(map[string]any, len(syncers)),
	}
	for _, s := range syncers {
		if !fullSync && !slices.Contains(keys, s.Key()) {
			continue
		}
		d, err := s.Collect()
		if err != nil {
			log.Debug().Err(err).Msgf("Failed to collect %s data.", s.Key())
			continue
		}
		snap.data[s.Key()] = d
		snap.hashes[s.Key()] = s.ComputeHash(d)
	}
	return snap
}

func (s syncSnapshot) empty() bool { return len(s.hashes) == 0 }

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

// syncHashHeader returns headers with X-Sync-Hash, or nil if hash is empty.
func syncHashHeader(hash string) scheduler.Headers {
	if hash == "" {
		return nil
	}
	return scheduler.Headers{"X-Sync-Hash": hash}
}

// computeFingerprint returns a SHA-256 hash of the JSON-serialized data.
// Returns an empty string on serialization error, causing the server to always flag the category for sync.
func computeFingerprint(data any) string {
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(jsonBytes)
	return "sha256:" + hex.EncodeToString(hash[:])
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
	default:
		log.Error().Str("key", key).Msg("unknown sync key in assignToCommitData")
	}
}
