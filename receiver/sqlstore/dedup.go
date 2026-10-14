package sqlstore

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/easyssf/easyssf-go/receiver"
	"github.com/easyssf/easyssf-go/ssf"
)

const (
	cleanupInterval = time.Minute
	inProgress      = "IN_PROGRESS"
	processed       = "PROCESSED"
	// DefaultRetention is how long a processed SET or a pending acknowledgement is remembered
	// by default: 7 days.
	DefaultRetention = 7 * 24 * time.Hour
)

// JTIDedupStore is a receiver.JTIDedupStore that remembers processed SETs in a database table
// shared by the instances of an application (JdbcSsfJtiDedupStore in Java): a SET delivered to
// several of them or again after a restart is handled by one and skipped by the others, and a
// SET one instance is handling is left alone by the rest. Processing stays at least once, see
// receiver.JTIDedupStore.
//
// A claim inserts the row with the state IN_PROGRESS: the primary key of the table makes that
// atomic, and a second instance that meets the row leaves the SET alone. The handlers' success
// turns the state into PROCESSED. STATE_CHANGED_AT is the time of the last state change, so an
// IN_PROGRESS row older than the Lease (60 seconds by default) counts as abandoned by a crashed
// instance and the next claim takes it over. That STATE_CHANGED_AT is also the token of the
// claim: the success or failure of the handlers only changes the row while it still carries the
// token they were granted, so an instance that outlived the lease leaves the claim of the
// taker-over alone. A renewal moves STATE_CHANGED_AT forward the same way a take-over does,
// fenced by the current token, and the new value is the token of the renewed claim.
//
// SETs are forgotten after the Retention: the store deletes them when it is written to, at most
// once a minute, and PurgeExpired does so on demand. The table is checked or created with
// PrepareTable; the constructor does not touch the database. Set the exported fields before use.
type JTIDedupStore struct {
	// Retention is how long a processed SET is remembered, DefaultRetention if zero. Has to
	// cover the time the transmitter keeps trying to deliver a SET.
	Retention time.Duration
	// Lease is how long a claim holds before the SET counts as abandoned by a crashed instance
	// and is handled again; receiver.DefaultDedupLease if zero, longer than the longest
	// handler.
	Lease time.Duration
	// Clock is the clock of the store; the system clock if nil.
	Clock receiver.Clock

	ops           *Operations
	prefix        string
	table         string
	insert        string
	selectState   string
	moveClaim     string
	markProcessed string
	deleteClaim   string
	deleteExpired string
	mu            sync.Mutex
	nextCleanup   time.Time
}

// NewJTIDedupStore is a store on the table with the given prefix, see DefaultTablePrefix.
func NewJTIDedupStore(ops *Operations, prefix string) *JTIDedupStore {
	table := ProcessedSetTable(prefix)
	return &JTIDedupStore{
		ops: ops, prefix: prefix, table: table,
		insert:      fmt.Sprintf("INSERT INTO %s (ISSUER, JTI, STATE, STATE_CHANGED_AT) VALUES (?, ?, ?, ?)", table),
		selectState: fmt.Sprintf("SELECT STATE, STATE_CHANGED_AT FROM %s WHERE ISSUER = ? AND JTI = ?", table),
		// a take-over and a renewal both move the claim's token forward, fenced by the current one
		moveClaim: fmt.Sprintf("UPDATE %s SET STATE_CHANGED_AT = ? WHERE ISSUER = ? AND JTI = ? AND STATE = '%s' AND STATE_CHANGED_AT = ?", table, inProgress),
		// processed and forget are fenced by the claim's token, the STATE_CHANGED_AT of the claim
		markProcessed: fmt.Sprintf("UPDATE %s SET STATE = '%s', STATE_CHANGED_AT = ? WHERE ISSUER = ? AND JTI = ? AND STATE = '%s' AND STATE_CHANGED_AT = ?", table, processed, inProgress),
		deleteClaim:   fmt.Sprintf("DELETE FROM %s WHERE ISSUER = ? AND JTI = ? AND STATE = '%s' AND STATE_CHANGED_AT = ?", table, inProgress),
		deleteExpired: fmt.Sprintf("DELETE FROM %s WHERE STATE_CHANGED_AT < ?", table),
	}
}

// Table is the name of the table.
func (s *JTIDedupStore) Table() string { return s.table }

// Name implements ExpiringStore.
func (s *JTIDedupStore) Name() string { return "JTIDedupStore" }

func (s *JTIDedupStore) now() time.Time {
	if s.Clock == nil {
		return time.Now()
	}
	return s.Clock()
}

func (s *JTIDedupStore) retention() time.Duration {
	if s.Retention <= 0 {
		return DefaultRetention
	}
	return s.Retention
}

func (s *JTIDedupStore) lease() time.Duration {
	if s.Lease <= 0 {
		return receiver.DefaultDedupLease
	}
	return s.Lease
}

// PrepareTable makes sure the table exists and has the columns of this release, see
// PrepareTable of the package. create says whether to create a missing table and to add missing
// columns; hint is what else the application could do, for the message.
func (s *JTIDedupStore) PrepareTable(ctx context.Context, create bool, hint string) error {
	return PrepareTable(ctx, s.ops, s.table, CreateProcessedSetTable(s.prefix), ProcessedSetUpgrades(s.prefix), create, hint)
}

// state reads the row of the SET; found is false if there is none.
func (s *JTIDedupStore) state(ctx context.Context, token *ssf.EventToken) (state string, since int64, found bool, err error) {
	rows, err := s.ops.Query(ctx, s.selectState, 1, token.Issuer(), token.JTI())
	if err != nil || len(rows) == 0 {
		return "", 0, false, err
	}
	since, _ = rows[0].Int64(1)
	return rows[0].String(0), since, true, nil
}

func (s *JTIDedupStore) removeExpiredIfDue(ctx context.Context, now time.Time) error {
	s.mu.Lock()
	due := s.nextCleanup.IsZero() || now.After(s.nextCleanup)
	s.mu.Unlock()
	if !due {
		return nil
	}
	_, err := s.PurgeExpired(ctx)
	return err
}

// Claim implements receiver.JTIDedupStore.
func (s *JTIDedupStore) Claim(ctx context.Context, token *ssf.EventToken) (receiver.JTIClaim, error) {
	now := s.now()
	if err := s.removeExpiredIfDue(ctx, now); err != nil {
		return receiver.JTIClaim{}, err
	}
	claimToken := millis(now)
	_, err := s.ops.Update(ctx, s.insert, token.Issuer(), token.JTI(), inProgress, claimToken)
	if err == nil {
		return receiver.JTIClaim{State: receiver.Granted, Token: claimToken}, nil
	}
	if !IsDuplicateKey(err) {
		return receiver.JTIClaim{}, err
	}
	state, since, found, err := s.state(ctx, token)
	if err != nil {
		return receiver.JTIClaim{}, err
	}
	if !found {
		// deleted in between: the redelivery will be claimed
		return receiver.JTIClaim{State: receiver.InProgress}, nil
	}
	if state == processed {
		return receiver.JTIClaim{State: receiver.Processed}, nil
	}
	if since+s.lease().Milliseconds() <= claimToken {
		// abandoned: take it over, unless another instance did just now. The new
		// STATE_CHANGED_AT is the token of the new claim; the old holder's token no longer
		// matches, so it can neither complete nor forget this claim.
		taken, err := s.ops.Update(ctx, s.moveClaim, claimToken, token.Issuer(), token.JTI(), since)
		if err != nil {
			return receiver.JTIClaim{}, err
		}
		if taken == 1 {
			return receiver.JTIClaim{State: receiver.Granted, Token: claimToken}, nil
		}
	}
	return receiver.JTIClaim{State: receiver.InProgress}, nil
}

// Processed implements receiver.JTIDedupStore.
func (s *JTIDedupStore) Processed(ctx context.Context, token *ssf.EventToken, claim receiver.JTIClaim) error {
	now := millis(s.now())
	updated, err := s.ops.Update(ctx, s.markProcessed, now, token.Issuer(), token.JTI(), claim.Token)
	if err != nil {
		return err
	}
	if updated > 0 {
		return nil
	}
	if _, _, found, err := s.state(ctx, token); err != nil || found {
		// otherwise the claim was taken over after the lease: the SET belongs to the new holder
		return err
	}
	// the claim was purged in between: record the success anyway. A duplicate means another
	// instance claimed the SET since, which then owns it.
	if _, err := s.ops.Update(ctx, s.insert, token.Issuer(), token.JTI(), processed, now); err != nil && !IsDuplicateKey(err) {
		return err
	}
	return nil
}

// Forget implements receiver.JTIDedupStore.
func (s *JTIDedupStore) Forget(ctx context.Context, token *ssf.EventToken, claim receiver.JTIClaim) error {
	_, err := s.ops.Update(ctx, s.deleteClaim, token.Issuer(), token.JTI(), claim.Token)
	return err
}

// Renew implements receiver.JTIDedupStore.
func (s *JTIDedupStore) Renew(ctx context.Context, token *ssf.EventToken, claim receiver.JTIClaim) (receiver.JTIClaim, bool, error) {
	// the new STATE_CHANGED_AT is the token of the renewed claim: later than the old one even
	// within the same millisecond, so that the row is seen as changed
	renewedToken := max(millis(s.now()), claim.Token+1)
	renewed, err := s.ops.Update(ctx, s.moveClaim, renewedToken, token.Issuer(), token.JTI(), claim.Token)
	if err != nil {
		return claim, false, err
	}
	if renewed != 1 {
		return claim, false, nil
	}
	return receiver.JTIClaim{State: receiver.Granted, Token: renewedToken}, true, nil
}

// PurgeExpired implements ExpiringStore.
func (s *JTIDedupStore) PurgeExpired(ctx context.Context) (int64, error) {
	now := s.now()
	s.mu.Lock()
	s.nextCleanup = now.Add(cleanupInterval)
	s.mu.Unlock()
	return s.ops.Update(ctx, s.deleteExpired, millis(now)-s.retention().Milliseconds())
}
