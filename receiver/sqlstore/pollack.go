package sqlstore

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/easyssf/easyssf-go/receiver"
)

// MaxDescriptionLength is the length the ERROR_DESCRIPTION column holds; longer descriptions
// are cut.
const MaxDescriptionLength = 1024

// DefaultDeleteBatchSize is how many entries one DELETE removes by default; databases limit the
// number of parameters of a statement.
const DefaultDeleteBatchSize = 100

// PollAckStore is a receiver.PollAckStore that keeps the acknowledgements a poller owes its
// transmitter in a database table (JdbcSsfPollAckStore in Java), so that they survive a
// restart: a SET handled right before the application stopped is acknowledged with the first
// poll after it started again, instead of being delivered once more.
//
// Entries a transmitter never accepts are forgotten after the Retention (DefaultRetention by
// default): the store deletes them when it is written to, at most once a minute, and
// PurgeExpired does so on demand.
type PollAckStore struct {
	// Retention is how long an entry the transmitter does not accept is kept; DefaultRetention
	// if zero.
	Retention time.Duration
	// DeleteBatchSize is how many entries one DELETE statement removes (JTI IN (...));
	// DefaultDeleteBatchSize if zero.
	DeleteBatchSize int
	// Clock is the clock of the store; the system clock if nil.
	Clock receiver.Clock

	ops           *Operations
	prefix        string
	table         string
	insert        string
	selectPending string
	deletePrefix  string
	count         string
	deleteExpired string
	mu            sync.Mutex
	nextCleanup   time.Time
}

// NewPollAckStore is a store on the table with the given prefix.
func NewPollAckStore(ops *Operations, prefix string) *PollAckStore {
	table := PollAckTable(prefix)
	return &PollAckStore{
		ops: ops, prefix: prefix, table: table,
		insert: fmt.Sprintf("INSERT INTO %s (ISSUER, JTI, ERROR_CODE, ERROR_DESCRIPTION, RECORDED_AT) VALUES (?, ?, ?, ?, ?)", table),
		// the limit is applied by reading no further, the SQL for it differs between databases
		selectPending: fmt.Sprintf("SELECT JTI, ERROR_CODE, ERROR_DESCRIPTION FROM %s WHERE ISSUER = ? ORDER BY RECORDED_AT, JTI", table),
		deletePrefix:  fmt.Sprintf("DELETE FROM %s WHERE ISSUER = ? AND JTI IN (", table),
		count:         fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE ISSUER = ?", table),
		deleteExpired: fmt.Sprintf("DELETE FROM %s WHERE RECORDED_AT < ?", table),
	}
}

// Table is the name of the table.
func (s *PollAckStore) Table() string { return s.table }

// Name implements ExpiringStore.
func (s *PollAckStore) Name() string { return "PollAckStore" }

func (s *PollAckStore) now() time.Time {
	if s.Clock == nil {
		return time.Now()
	}
	return s.Clock()
}

// PrepareTable makes sure the table exists, see PrepareTable of the package.
func (s *PollAckStore) PrepareTable(ctx context.Context, create bool, hint string) error {
	return PrepareTable(ctx, s.ops, s.table, CreatePollAckTable(s.prefix), nil, create, hint)
}

// Record implements receiver.PollAckStore.
func (s *PollAckStore) Record(ctx context.Context, issuer string, ack receiver.PendingAck) error {
	now := s.now()
	s.mu.Lock()
	due := s.nextCleanup.IsZero() || now.After(s.nextCleanup)
	s.mu.Unlock()
	if due {
		if _, err := s.PurgeExpired(ctx); err != nil {
			return err
		}
	}
	var code, description any
	if ack.IsError() {
		code = string(ack.Error)
		if ack.Description != "" {
			runes := []rune(ack.Description)
			if len(runes) > MaxDescriptionLength {
				runes = runes[:MaxDescriptionLength]
			}
			description = string(runes)
		}
	}
	_, err := s.ops.Update(ctx, s.insert, issuer, ack.JTI, code, description, millis(now))
	if err != nil && !IsDuplicateKey(err) {
		return err
	}
	// a duplicate was recorded already, for example a SET delivered twice before it was
	// acknowledged
	return nil
}

// Pending implements receiver.PollAckStore.
func (s *PollAckStore) Pending(ctx context.Context, issuer string, limit int) ([]receiver.PendingAck, error) {
	rows, err := s.ops.Query(ctx, s.selectPending, limit, issuer)
	if err != nil {
		return nil, err
	}
	pending := make([]receiver.PendingAck, 0, len(rows))
	for _, row := range rows {
		pending = append(pending, receiver.PendingAck{JTI: row.String(0), Error: receiver.ErrorCode(row.String(1)), Description: row.String(2)})
	}
	return pending, nil
}

// Remove implements receiver.PollAckStore.
func (s *PollAckStore) Remove(ctx context.Context, issuer string, jtis []string) error {
	batch := s.DeleteBatchSize
	if batch <= 0 {
		batch = DefaultDeleteBatchSize
	}
	for start := 0; start < len(jtis); start += batch {
		chunk := jtis[start:min(start+batch, len(jtis))]
		args := make([]any, 0, len(chunk)+1)
		args = append(args, issuer)
		for _, jti := range chunk {
			args = append(args, jti)
		}
		sql := s.deletePrefix + strings.TrimSuffix(strings.Repeat("?, ", len(chunk)), ", ") + ")"
		if _, err := s.ops.Update(ctx, sql, args...); err != nil {
			return err
		}
	}
	return nil
}

// Size implements receiver.PollAckStore.
func (s *PollAckStore) Size(ctx context.Context, issuer string) (int, error) {
	rows, err := s.ops.Query(ctx, s.count, 1, issuer)
	if err != nil || len(rows) == 0 {
		return 0, err
	}
	n, _ := rows[0].Int64(0)
	return int(max(n, 0)), nil
}

// PurgeExpired implements ExpiringStore.
func (s *PollAckStore) PurgeExpired(ctx context.Context) (int64, error) {
	now := s.now()
	s.mu.Lock()
	s.nextCleanup = now.Add(cleanupInterval)
	s.mu.Unlock()
	retention := s.Retention
	if retention <= 0 {
		retention = DefaultRetention
	}
	return s.ops.Update(ctx, s.deleteExpired, millis(now)-retention.Milliseconds())
}
