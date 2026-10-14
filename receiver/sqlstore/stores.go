package sqlstore

import (
	"context"
	"log/slog"
	"time"

	"github.com/easyssf/easyssf-go/receiver"
)

// Stores are the database stores of the receiver, built from easyssf.receiver.data, dedup and
// revocation of its configuration: the counterpart of the JDBC auto-configuration of the Spring
// Boot starter and of AddDatabaseStores() in .NET.
type Stores struct {
	// Log is where the stores and the cleanup log; discarded if nil.
	Log *slog.Logger

	ops              *Operations
	enabled          bool
	initializeSchema string
	cleanupInterval  time.Duration
	dedup            *JTIDedupStore
	revocations      *TokenRevocationStore
	acks             *PollAckStore
}

const hint = "set easyssf.receiver.data.initialize-schema = \"always\" to have it created on startup, or set easyssf.receiver.data.enabled = false to keep the state of the receiver in memory"

// NewStores are the stores on ops with the settings of the configuration. clock is the clock
// of the stores, the system clock if nil.
func NewStores(ops *Operations, config receiver.Config) *Stores {
	data := config.Data
	mode, _ := data.SchemaInitialization()
	dedup := NewJTIDedupStore(ops, data.TablePrefix)
	dedup.Retention, dedup.Lease = config.Dedup.Retention.Std(), config.Dedup.Lease.Std()
	acks := NewPollAckStore(ops, data.TablePrefix)
	acks.Retention, acks.DeleteBatchSize = data.AckRetention.Std(), data.AckDeleteBatchSize
	return &Stores{
		ops: ops, enabled: data.Enabled, initializeSchema: mode, cleanupInterval: data.CleanupInterval.Std(),
		dedup:       dedup,
		revocations: NewTokenRevocationStore(ops, data.TablePrefix, config.Revocation.TTL.Std()),
		acks:        acks,
	}
}

// WithClock replaces the clock of the three stores, for tests.
func (s *Stores) WithClock(clock receiver.Clock) *Stores {
	s.dedup.Clock, s.revocations.Clock, s.acks.Clock = clock, clock, clock
	return s
}

// Operations is what the stores run their statements with.
func (s *Stores) Operations() *Operations { return s.ops }

// IsEnabled reports whether the stores are used, easyssf.receiver.data.enabled.
func (s *Stores) IsEnabled() bool { return s.enabled }

// JTIDedupStore is the dedup store.
func (s *Stores) JTIDedupStore() *JTIDedupStore { return s.dedup }

// TokenRevocationStore is the revocation store.
func (s *Stores) TokenRevocationStore() *TokenRevocationStore { return s.revocations }

// PollAckStore is the poll acknowledgement store.
func (s *Stores) PollAckStore() *PollAckStore { return s.acks }

// CreatesTables reports whether the tables are to be created, by
// easyssf.receiver.data.initialize-schema.
func (s *Stores) CreatesTables() bool {
	switch s.initializeSchema {
	case receiver.SchemaAlways:
		return true
	case receiver.SchemaNever:
		return false
	}
	return s.ops.IsEmbeddedDatabase()
}

// PrepareTables checks or creates the three tables, per easyssf.receiver.data.initialize-schema.
// Does nothing if the stores are disabled. It fails if a table is missing or outdated and is not
// to be changed, with the statements to run: better at startup than on the first event.
func (s *Stores) PrepareTables(ctx context.Context) error {
	if !s.enabled {
		return nil
	}
	create := s.CreatesTables()
	if err := s.dedup.PrepareTable(ctx, create, hint); err != nil {
		return err
	}
	if err := s.revocations.PrepareTable(ctx, create, hint); err != nil {
		return err
	}
	if err := s.acks.PrepareTable(ctx, create, hint); err != nil {
		return err
	}
	if s.Log != nil {
		s.Log.Info("The SSF receiver keeps its state in the database", "section", receiver.ConfigurationSection)
	}
	return nil
}

// Cleanup is a cleanup of the expired rows of the three stores every
// easyssf.receiver.data.cleanup-interval; start it with Cleanup.Start.
func (s *Stores) Cleanup() *Cleanup {
	var stores []ExpiringStore
	if s.enabled {
		stores = []ExpiringStore{s.dedup, s.revocations, s.acks}
	}
	cleanup := NewCleanup(stores, s.cleanupInterval)
	cleanup.Log = s.Log
	return cleanup
}

// Options give the receiver the three stores instead of its in-memory ones, unless the stores
// are disabled: pass them to receiver.New.
func (s *Stores) Options() []receiver.Option {
	if !s.enabled {
		return nil
	}
	return []receiver.Option{receiver.WithDedupStore(s.dedup), receiver.WithTokenRevocationStore(s.revocations), receiver.WithPollAckStore(s.acks)}
}
