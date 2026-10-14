package sqlstore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/easyssf/easyssf-go/receiver"
)

const (
	kindSession = "SESSION"
	kindSubject = "SUBJECT"
)

// TokenRevocationStore is a receiver.TokenRevocationStore that keeps revocations in a database
// table (JdbcSsfTokenRevocationStore in Java), so that all instances of a resource server reject
// the access tokens of a revoked session or subject, whichever instance received the event.
// Sessions and subjects are keyed by the issuer of their tokens.
//
// Checking an access token takes one query on the primary key of the table. Revocations are
// removed after the time to live: the store deletes them when it is written to, and
// PurgeExpired does so on demand.
type TokenRevocationStore struct {
	// Clock is the clock of the store; the system clock if nil.
	Clock receiver.Clock

	ops    *Operations
	prefix string
	table  string
	ttl    time.Duration
}

// NewTokenRevocationStore is a store on the table with the given prefix that remembers a
// revocation for ttl, at least the maximum access token lifetime; 24 hours if zero.
func NewTokenRevocationStore(ops *Operations, prefix string, ttl time.Duration) *TokenRevocationStore {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &TokenRevocationStore{ops: ops, prefix: prefix, table: RevocationTable(prefix), ttl: ttl}
}

// Table is the name of the table.
func (s *TokenRevocationStore) Table() string { return s.table }

// Name implements ExpiringStore.
func (s *TokenRevocationStore) Name() string { return "TokenRevocationStore" }

func (s *TokenRevocationStore) now() time.Time {
	if s.Clock == nil {
		return time.Now()
	}
	return s.Clock()
}

// PrepareTable makes sure the table exists, see PrepareTable of the package.
func (s *TokenRevocationStore) PrepareTable(ctx context.Context, create bool, hint string) error {
	return PrepareTable(ctx, s.ops, s.table, CreateRevocationTable(s.prefix), nil, create, hint)
}

func (s *TokenRevocationStore) revoke(ctx context.Context, kind, issuer, id string, revokedAt time.Time) error {
	if strings.TrimSpace(issuer) == "" || strings.TrimSpace(id) == "" {
		return errors.New("issuer and id must not be empty")
	}
	now := s.now()
	if _, err := s.PurgeExpired(ctx); err != nil {
		return err
	}
	expiresAt := millis(now.Add(s.ttl))
	updated, err := s.update(ctx, kind, issuer, id, millis(revokedAt), expiresAt)
	if err != nil || updated {
		return err
	}
	insert := fmt.Sprintf("INSERT INTO %s (KIND, ISSUER, ID, REVOKED_AT, EXPIRES_AT) VALUES (?, ?, ?, ?, ?)", s.table)
	_, err = s.ops.Update(ctx, insert, kind, issuer, id, millis(revokedAt), expiresAt)
	if err == nil {
		return nil
	}
	if IsDuplicateKey(err) {
		// revoked by another instance at the same time
		_, err = s.update(ctx, kind, issuer, id, millis(revokedAt), expiresAt)
	}
	return err
}

func (s *TokenRevocationStore) update(ctx context.Context, kind, issuer, id string, revokedAt, expiresAt int64) (bool, error) {
	update := fmt.Sprintf("UPDATE %s SET REVOKED_AT = ?, EXPIRES_AT = ? WHERE KIND = ? AND ISSUER = ? AND ID = ? AND REVOKED_AT <= ?", s.table)
	updated, err := s.ops.Update(ctx, update, revokedAt, expiresAt, kind, issuer, id, revokedAt)
	if err != nil {
		return false, err
	}
	if updated == 0 {
		// an event delivered late must not shorten a more recent revocation
		extend := fmt.Sprintf("UPDATE %s SET EXPIRES_AT = ? WHERE KIND = ? AND ISSUER = ? AND ID = ?", s.table)
		if updated, err = s.ops.Update(ctx, extend, expiresAt, kind, issuer, id); err != nil {
			return false, err
		}
	}
	return updated > 0, nil
}

// RevokeSession implements receiver.TokenRevocationStore.
func (s *TokenRevocationStore) RevokeSession(ctx context.Context, issuer, sessionID string) error {
	return s.revoke(ctx, kindSession, issuer, sessionID, s.now())
}

// RevokeSubject implements receiver.TokenRevocationStore.
func (s *TokenRevocationStore) RevokeSubject(ctx context.Context, issuer, subject string, revokedAt time.Time) error {
	return s.revoke(ctx, kindSubject, issuer, subject, revokedAt)
}

// IsSessionRevoked implements receiver.TokenRevocationStore.
func (s *TokenRevocationStore) IsSessionRevoked(ctx context.Context, issuer, sessionID string) (bool, error) {
	query := fmt.Sprintf("SELECT KIND FROM %s WHERE KIND = ? AND ISSUER = ? AND ID = ? AND EXPIRES_AT > ?", s.table)
	rows, err := s.ops.Query(ctx, query, 1, kindSession, issuer, sessionID, millis(s.now()))
	return len(rows) > 0, err
}

// SubjectRevokedAt implements receiver.TokenRevocationStore.
func (s *TokenRevocationStore) SubjectRevokedAt(ctx context.Context, issuer, subject string) (time.Time, error) {
	query := fmt.Sprintf("SELECT REVOKED_AT FROM %s WHERE KIND = ? AND ISSUER = ? AND ID = ? AND EXPIRES_AT > ?", s.table)
	rows, err := s.ops.Query(ctx, query, 1, kindSubject, issuer, subject, millis(s.now()))
	if err != nil || len(rows) == 0 {
		return time.Time{}, err
	}
	revokedAt, ok := rows[0].Int64(0)
	if !ok {
		return time.Time{}, nil
	}
	return fromMillis(revokedAt), nil
}

// PurgeExpired implements ExpiringStore.
func (s *TokenRevocationStore) PurgeExpired(ctx context.Context) (int64, error) {
	return s.ops.Update(ctx, fmt.Sprintf("DELETE FROM %s WHERE EXPIRES_AT <= ?", s.table), millis(s.now()))
}
