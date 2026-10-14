package sqlstore_test

// AbstractJdbcSsfStoresTests and DataSourceSsfJdbcOperationsTests of the Java library, on SQLite
// always, and on PostgreSQL and MySQL when EASYSSF_DATABASE_TESTS=true and EASYSSF_POSTGRES_URL
// / EASYSSF_MYSQL_URL name the databases.

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	"github.com/easyssf/easyssf-go/receiver"
	"github.com/easyssf/easyssf-go/receiver/sqlstore"
	"github.com/easyssf/easyssf-go/ssf"
)

const prefix = "EASYSSF_"

var ctx = context.Background()

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock { return &testClock{now: time.Now()} }

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// sharedDatabases serialises the tests on PostgreSQL and MySQL: go test runs the tests of a
// package in parallel only when asked, but the databases are shared by all of them, each
// dropping and creating the same tables. SQLite is in memory and private to the test.
var sharedDatabases sync.Mutex

type database struct {
	name string
	ops  *sqlstore.Operations
}

// databases are every database the tests run on: SQLite in memory always, the others when opted
// in.
func databases(t *testing.T) []database {
	t.Helper()
	sqlite, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	sqlite.SetMaxOpenConns(1)
	t.Cleanup(func() { sqlite.Close() })
	all := []database{{"sqlite", sqlstore.NewOperations(sqlite, sqlstore.SQLite)}}
	if os.Getenv("EASYSSF_DATABASE_TESTS") != "true" {
		return all
	}
	sharedDatabases.Lock()
	t.Cleanup(sharedDatabases.Unlock)
	for _, candidate := range []struct {
		name, driver, env string
		dialect           sqlstore.Dialect
	}{{"postgres", "pgx", "EASYSSF_POSTGRES_URL", sqlstore.PostgreSQL}, {"mysql", "mysql", "EASYSSF_MYSQL_URL", sqlstore.MySQL}} {
		url := os.Getenv(candidate.env)
		if url == "" {
			continue
		}
		db, err := sql.Open(candidate.driver, url)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		ops := sqlstore.NewOperations(db, candidate.dialect)
		for _, table := range []string{"EASYSSF_PROCESSED_SET", "EASYSSF_REVOCATION", "EASYSSF_POLL_ACK", "X_PROCESSED_SET"} {
			_ = ops.Execute(ctx, "DROP TABLE "+table)
		}
		all = append(all, database{candidate.name, ops})
	}
	return all
}

func createTables(t *testing.T, ops *sqlstore.Operations) {
	t.Helper()
	for _, statement := range sqlstore.Statements(sqlstore.SchemaSQL) {
		if err := ops.Execute(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
}

func token(jti string) *ssf.EventToken {
	return ssf.EventTokenFromClaims(ssf.Claims{"jti": jti, "iss": "https://t.example", "iat": float64(1), "events": ssf.Claims{"e": ssf.Claims{}}})
}

func claimState(t *testing.T, store receiver.JTIDedupStore, set *ssf.EventToken) receiver.JTIClaim {
	t.Helper()
	claim, err := store.Claim(ctx, set)
	if err != nil {
		t.Fatal(err)
	}
	return claim
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestSchemaFileMatchesTheStatementsThatCreateTheTables(t *testing.T) {
	var expected []string
	for _, statements := range [][]string{sqlstore.CreateProcessedSetTable(prefix), sqlstore.CreateRevocationTable(prefix), sqlstore.CreatePollAckTable(prefix)} {
		for _, statement := range statements {
			expected = append(expected, strings.Join(strings.Fields(statement), " "))
		}
	}
	actual := sqlstore.Statements(sqlstore.SchemaSQL)
	if strings.Join(actual, "\n") != strings.Join(expected, "\n") {
		t.Fatalf("schema.sql differs from the statements:\n%v\n%v", actual, expected)
	}
	if sqlstore.Migrations[0].Name != "V0_1_0__processed_sets_and_revocations.sql" {
		t.Fatal("oldest first")
	}
	for _, migration := range sqlstore.Migrations {
		if len(sqlstore.Statements(migration.SQL)) == 0 {
			t.Fatal(migration.Name)
		}
	}
}

func TestPlaceholdersAreRewrittenForPostgresOnly(t *testing.T) {
	if sql, _ := sqlstore.Placeholders("SELECT ? , ?", 2, sqlstore.PostgreSQL); sql != "SELECT $1 , $2" {
		t.Fatal(sql)
	}
	if sql, _ := sqlstore.Placeholders("SELECT ? , ?", 2, sqlstore.SQLite); sql != "SELECT ? , ?" {
		t.Fatal(sql)
	}
	if _, err := sqlstore.Placeholders("SELECT ?", 2, sqlstore.PostgreSQL); err == nil {
		t.Fatal("count")
	}
	if _, err := sqlstore.Placeholders("SELECT 1", 1, sqlstore.MySQL); err == nil {
		t.Fatal("count")
	}
	if dialect, ok := sqlstore.DialectFor("pgx"); !ok || dialect.Name != "postgres" {
		t.Fatal("pgx")
	}
	if _, ok := sqlstore.DialectFor("oracle"); ok {
		t.Fatal("unknown")
	}
}

func TestMigrationScriptsLeadToTheCurrentSchema(t *testing.T) {
	for _, db := range databases(t) {
		for _, migration := range sqlstore.Migrations {
			for _, statement := range sqlstore.Statements(migration.SQL) {
				if err := db.ops.Execute(ctx, statement); err != nil {
					t.Fatalf("%s: %v", db.name, err)
				}
			}
		}
		if missing := sqlstore.MissingUpgrades(ctx, db.ops, "EASYSSF_PROCESSED_SET", sqlstore.ProcessedSetUpgrades(prefix)); len(missing) != 0 {
			t.Fatalf("%s: %v", db.name, missing)
		}
		for _, table := range []string{"EASYSSF_REVOCATION", "EASYSSF_POLL_ACK"} {
			if exists, err := db.ops.TableExists(ctx, table); err != nil || !exists {
				t.Fatalf("%s: %v", db.name, err)
			}
		}
		// the stores work on the migrated tables
		store := sqlstore.NewJTIDedupStore(db.ops, prefix)
		must(t, store.PrepareTable(ctx, false, ""))
		if !claimState(t, store, token("1")).IsGranted() {
			t.Fatal(db.name)
		}
	}
}

func TestMissingColumnsAreAddedWhereTablesMayBeCreatedAndReportedOtherwise(t *testing.T) {
	for _, db := range databases(t) {
		// the table of 0.1.0
		for _, statement := range sqlstore.Statements(sqlstore.Migrations[0].SQL) {
			must(t, db.ops.Execute(ctx, statement))
		}
		store := sqlstore.NewJTIDedupStore(db.ops, prefix)
		err := store.PrepareTable(ctx, false, "do something")
		if err == nil || !strings.Contains(err.Error(), "predates this release") || !strings.Contains(err.Error(), "STATE") ||
			!strings.Contains(err.Error(), "RENAME COLUMN") || !strings.Contains(err.Error(), "do something") {
			t.Fatalf("%s: %v", db.name, err)
		}
		must(t, store.PrepareTable(ctx, true, ""))
		if missing := sqlstore.MissingUpgrades(ctx, db.ops, "EASYSSF_PROCESSED_SET", sqlstore.ProcessedSetUpgrades(prefix)); len(missing) != 0 {
			t.Fatalf("%s: %v", db.name, missing)
		}
		if !claimState(t, store, token("1")).IsGranted() {
			t.Fatal(db.name)
		}
	}
}

func TestTableOf030IsUpgradedByRenamingTheColumn(t *testing.T) {
	for _, db := range databases(t) {
		for _, migration := range sqlstore.Migrations[:2] {
			for _, statement := range sqlstore.Statements(migration.SQL) {
				must(t, db.ops.Execute(ctx, statement))
			}
		}
		_, err := db.ops.Update(ctx, "INSERT INTO EASYSSF_PROCESSED_SET (ISSUER, JTI, PROCESSED_AT, STATE) VALUES (?, ?, ?, ?)", "https://t.example", "old", time.Now().UnixMilli(), "PROCESSED")
		must(t, err)
		store := sqlstore.NewJTIDedupStore(db.ops, prefix)
		must(t, store.PrepareTable(ctx, true, ""))
		if claimState(t, store, token("old")).State != receiver.Processed {
			t.Fatalf("%s: the row survived the rename", db.name)
		}
	}
}

func TestPreparingTablesIsRepeatableAndReportsMissingTables(t *testing.T) {
	for _, db := range databases(t) {
		store := sqlstore.NewTokenRevocationStore(db.ops, prefix, time.Minute)
		err := store.PrepareTable(ctx, false, "or else")
		if err == nil || !strings.Contains(err.Error(), "does not exist") || !strings.Contains(err.Error(), "or else") {
			t.Fatalf("%s: %v", db.name, err)
		}
		must(t, store.PrepareTable(ctx, true, ""))
		must(t, store.PrepareTable(ctx, true, ""))
		must(t, store.PrepareTable(ctx, false, ""))
		acks := sqlstore.NewPollAckStore(db.ops, prefix)
		must(t, acks.PrepareTable(ctx, true, ""))
		must(t, acks.PrepareTable(ctx, false, ""))
	}
}

func TestTablePrefixIsConfigurableButRestricted(t *testing.T) {
	for _, db := range databases(t) {
		store := sqlstore.NewJTIDedupStore(db.ops, "X_")
		if store.Table() != "X_PROCESSED_SET" {
			t.Fatal(store.Table())
		}
		must(t, store.PrepareTable(ctx, true, ""))
		if exists, _ := db.ops.TableExists(ctx, "X_PROCESSED_SET"); !exists {
			t.Fatal(db.name)
		}
	}
	defer func() {
		if recover() == nil {
			t.Fatal("a bad prefix panics")
		}
	}()
	sqlstore.ProcessedSetTable("bad prefix")
}

func TestSetIsSeenBeforeOnceItWasRecorded(t *testing.T) {
	for _, db := range databases(t) {
		createTables(t, db.ops)
		store := sqlstore.NewJTIDedupStore(db.ops, prefix)
		set := token("1")
		claim := claimState(t, store, set)
		if !claim.IsGranted() {
			t.Fatal(db.name)
		}
		must(t, store.Processed(ctx, set, claim))
		if claimState(t, store, set).State != receiver.Processed {
			t.Fatal("processed")
		}
		// another issuer with the same jti is another SET
		other := ssf.EventTokenFromClaims(ssf.Claims{"jti": "1", "iss": "https://other.example", "iat": float64(1), "events": ssf.Claims{"e": ssf.Claims{}}})
		if !claimState(t, store, other).IsGranted() {
			t.Fatal("other issuer")
		}
		// processed SETs are shared between instances
		if claimState(t, sqlstore.NewJTIDedupStore(db.ops, prefix), set).State != receiver.Processed {
			t.Fatal("shared")
		}
	}
}

func TestClaimTellsWhetherAnotherInstanceIsOnTheSet(t *testing.T) {
	for _, db := range databases(t) {
		createTables(t, db.ops)
		first := sqlstore.NewJTIDedupStore(db.ops, prefix)
		second := sqlstore.NewJTIDedupStore(db.ops, prefix)
		set := token("1")
		claim := claimState(t, first, set)
		if claimState(t, second, set).State != receiver.InProgress {
			t.Fatal(db.name)
		}
		must(t, first.Forget(ctx, set, claim))
		if !claimState(t, second, set).IsGranted() {
			t.Fatal("forgotten")
		}
	}
}

func TestAbandonedClaimIsTakenOverAfterTheLease(t *testing.T) {
	for _, db := range databases(t) {
		createTables(t, db.ops)
		clock := newTestClock()
		store := sqlstore.NewJTIDedupStore(db.ops, prefix)
		store.Lease, store.Clock = time.Minute, clock.Now
		set := token("1")
		first := claimState(t, store, set)
		clock.Advance(59 * time.Second)
		if claimState(t, store, set).State != receiver.InProgress {
			t.Fatal(db.name)
		}
		clock.Advance(2 * time.Second)
		second := claimState(t, store, set)
		if !second.IsGranted() || second.Token == first.Token {
			t.Fatal("taken over")
		}
		// renewed claims outlive the lease
		clock.Advance(40 * time.Second)
		renewed, ok, err := store.Renew(ctx, set, second)
		if err != nil || !ok {
			t.Fatal(err)
		}
		clock.Advance(40 * time.Second)
		if claimState(t, store, set).State != receiver.InProgress {
			t.Fatal("renewed")
		}
		must(t, store.Processed(ctx, set, renewed))
		if claimState(t, store, set).State != receiver.Processed {
			t.Fatal("processed")
		}
	}
}

func TestLateInstanceCanNeitherCompleteNorForgetAClaimTakenOverFromIt(t *testing.T) {
	for _, db := range databases(t) {
		createTables(t, db.ops)
		clock := newTestClock()
		store := sqlstore.NewJTIDedupStore(db.ops, prefix)
		store.Lease, store.Clock = time.Minute, clock.Now
		set := token("1")
		first := claimState(t, store, set)
		clock.Advance(61 * time.Second)
		second := claimState(t, store, set)
		must(t, store.Processed(ctx, set, first))
		if claimState(t, store, set).State != receiver.InProgress {
			t.Fatal(db.name)
		}
		must(t, store.Forget(ctx, set, first))
		if claimState(t, store, set).State != receiver.InProgress {
			t.Fatal("not forgotten")
		}
		if _, ok, _ := store.Renew(ctx, set, first); ok {
			t.Fatal("not renewed")
		}
		must(t, store.Processed(ctx, set, second))
		if claimState(t, store, set).State != receiver.Processed {
			t.Fatal("processed by the second")
		}
	}
}

func TestProcessedAfterThePurgeRecordsTheSetAgain(t *testing.T) {
	for _, db := range databases(t) {
		createTables(t, db.ops)
		clock := newTestClock()
		store := sqlstore.NewJTIDedupStore(db.ops, prefix)
		store.Retention, store.Clock = time.Hour, clock.Now
		set := token("1")
		claim := claimState(t, store, set)
		clock.Advance(3601 * time.Second)
		if purged, err := store.PurgeExpired(ctx); err != nil || purged != 1 {
			t.Fatalf("%s: %d %v", db.name, purged, err)
		}
		must(t, store.Processed(ctx, set, claim))
		if claimState(t, store, set).State != receiver.Processed {
			t.Fatal("recorded again")
		}
	}
}

func TestProcessedSetsAreForgottenAfterTheRetentionTime(t *testing.T) {
	for _, db := range databases(t) {
		createTables(t, db.ops)
		clock := newTestClock()
		store := sqlstore.NewJTIDedupStore(db.ops, prefix)
		store.Retention, store.Clock = time.Hour, clock.Now
		set := token("1")
		claim := claimState(t, store, set)
		must(t, store.Processed(ctx, set, claim))
		clock.Advance(3599 * time.Second)
		if claimState(t, store, set).State != receiver.Processed {
			t.Fatal(db.name)
		}
		clock.Advance(120 * time.Second)
		// the next claim purges first, at most once a minute
		if !claimState(t, store, set).IsGranted() {
			t.Fatal("forgotten")
		}
	}
}

func revokedClaims(issuer, subject, session string, issuedAt time.Time) receiver.TokenClaims {
	return receiver.TokenClaims{Issuer: issuer, Subject: subject, SessionID: session, IssuedAt: issuedAt}
}

func isRevoked(t *testing.T, store receiver.TokenRevocationStore, claims receiver.TokenClaims) bool {
	t.Helper()
	revoked, err := receiver.IsRevoked(ctx, store, claims)
	must(t, err)
	return revoked
}

func TestRevokedSessionRevokesItsTokensWheneverTheyWereIssued(t *testing.T) {
	for _, db := range databases(t) {
		createTables(t, db.ops)
		store := sqlstore.NewTokenRevocationStore(db.ops, prefix, time.Hour)
		must(t, store.RevokeSession(ctx, "https://idp.example", "s1"))
		if revoked, _ := store.IsSessionRevoked(ctx, "https://idp.example", "s1"); !revoked {
			t.Fatal(db.name)
		}
		if !isRevoked(t, store, revokedClaims("https://idp.example", "alice", "s1", time.Now().Add(10*time.Minute))) ||
			isRevoked(t, store, revokedClaims("https://idp.example", "alice", "s2", time.Time{})) ||
			isRevoked(t, store, revokedClaims("https://other.example", "", "s1", time.Time{})) ||
			isRevoked(t, store, receiver.TokenClaims{}) {
			t.Fatal("session")
		}
		// revocations are shared between instances, revoking again extends the expiry
		second := sqlstore.NewTokenRevocationStore(db.ops, prefix, time.Hour)
		if revoked, _ := second.IsSessionRevoked(ctx, "https://idp.example", "s1"); !revoked {
			t.Fatal("shared")
		}
		must(t, second.RevokeSession(ctx, "https://idp.example", "s1"))
	}
}

func TestRevokedSubjectRevokesTokensIssuedUpToTheRevocation(t *testing.T) {
	for _, db := range databases(t) {
		createTables(t, db.ops)
		store := sqlstore.NewTokenRevocationStore(db.ops, prefix, time.Hour)
		revokedAt := time.Now()
		must(t, store.RevokeSubject(ctx, "https://idp.example", "alice", revokedAt))
		stored, err := store.SubjectRevokedAt(ctx, "https://idp.example", "alice")
		if err != nil || stored.IsZero() || stored.Sub(revokedAt).Abs() >= 2*time.Millisecond {
			t.Fatalf("%s: %v %v", db.name, stored, err)
		}
		if !isRevoked(t, store, revokedClaims("https://idp.example", "alice", "", revokedAt.Add(-time.Second))) ||
			!isRevoked(t, store, revokedClaims("https://idp.example", "alice", "", time.Time{})) ||
			isRevoked(t, store, revokedClaims("https://idp.example", "alice", "", revokedAt.Add(time.Minute))) ||
			isRevoked(t, store, revokedClaims("https://idp.example", "bob", "s9", time.Time{})) {
			t.Fatal("subject")
		}
		if at, _ := store.SubjectRevokedAt(ctx, "https://idp.example", "bob"); !at.IsZero() {
			t.Fatal("bob")
		}
	}
}

func TestEventDeliveredLateDoesNotShortenMoreRecentRevocation(t *testing.T) {
	for _, db := range databases(t) {
		createTables(t, db.ops)
		clock := newTestClock()
		store := sqlstore.NewTokenRevocationStore(db.ops, prefix, time.Hour)
		store.Clock = clock.Now
		now := clock.Now()
		must(t, store.RevokeSubject(ctx, "https://idp.example", "alice", now))
		must(t, store.RevokeSubject(ctx, "https://idp.example", "alice", now.Add(-10*time.Minute)))
		stored, _ := store.SubjectRevokedAt(ctx, "https://idp.example", "alice")
		if stored.Sub(now).Abs() >= 2*time.Millisecond {
			t.Fatalf("%s: %v", db.name, stored)
		}
		if !isRevoked(t, store, revokedClaims("https://idp.example", "alice", "", now.Add(-5*time.Minute))) {
			t.Fatal("revoked")
		}
	}
}

func TestRevocationsExpireAndAreRemoved(t *testing.T) {
	for _, db := range databases(t) {
		createTables(t, db.ops)
		clock := newTestClock()
		store := sqlstore.NewTokenRevocationStore(db.ops, prefix, time.Minute)
		store.Clock = clock.Now
		must(t, store.RevokeSession(ctx, "https://idp.example", "s1"))
		must(t, store.RevokeSubject(ctx, "https://idp.example", "alice", clock.Now()))
		clock.Advance(59 * time.Second)
		if revoked, _ := store.IsSessionRevoked(ctx, "https://idp.example", "s1"); !revoked {
			t.Fatal(db.name)
		}
		clock.Advance(2 * time.Second)
		if revoked, _ := store.IsSessionRevoked(ctx, "https://idp.example", "s1"); revoked {
			t.Fatal("expired")
		}
		if at, _ := store.SubjectRevokedAt(ctx, "https://idp.example", "alice"); !at.IsZero() {
			t.Fatal("expired subject")
		}
		if purged, _ := store.PurgeExpired(ctx); purged != 2 {
			t.Fatalf("%d", purged)
		}
		if purged, _ := store.PurgeExpired(ctx); purged != 0 {
			t.Fatalf("%d", purged)
		}
	}
}

func TestAcknowledgementsWaitUntilRemovedAndAreSharedBetweenInstances(t *testing.T) {
	for _, db := range databases(t) {
		createTables(t, db.ops)
		first := sqlstore.NewPollAckStore(db.ops, prefix)
		second := sqlstore.NewPollAckStore(db.ops, prefix)
		must(t, first.Record(ctx, "https://t.example", receiver.Ack("1")))
		must(t, first.Record(ctx, "https://t.example", receiver.AckError("2", receiver.InvalidRequest, "bad")))
		must(t, first.Record(ctx, "https://t.example", receiver.Ack("2")))
		must(t, first.Record(ctx, "https://other.example", receiver.Ack("3")))
		pending, err := second.Pending(ctx, "https://t.example", 10)
		if err != nil || len(pending) != 2 || pending[0] != receiver.Ack("1") || pending[1] != receiver.AckError("2", receiver.InvalidRequest, "bad") {
			t.Fatalf("%s: %v %v", db.name, pending, err)
		}
		if size, _ := second.Size(ctx, "https://t.example"); size != 2 {
			t.Fatal("size")
		}
		if size, _ := second.Size(ctx, "https://nobody.example"); size != 0 {
			t.Fatal("nobody")
		}
		must(t, second.Remove(ctx, "https://t.example", []string{"1", "missing"}))
		pending, _ = first.Pending(ctx, "https://t.example", 10)
		if len(pending) != 1 || pending[0].JTI != "2" {
			t.Fatal("removed")
		}
		if size, _ := first.Size(ctx, "https://other.example"); size != 1 {
			t.Fatal("other")
		}
	}
}

func TestManyAcknowledgementsAreListedWithALimitAndRemovedInChunks(t *testing.T) {
	for _, db := range databases(t) {
		createTables(t, db.ops)
		clock := newTestClock()
		store := sqlstore.NewPollAckStore(db.ops, prefix)
		store.DeleteBatchSize, store.Clock = 3, clock.Now
		var jtis []string
		for i := 0; i < 10; i++ {
			jti := "jti-" + string(rune('a'+i))
			jtis = append(jtis, jti)
			must(t, store.Record(ctx, "https://t.example", receiver.Ack(jti)))
			clock.Advance(time.Millisecond)
		}
		pending, _ := store.Pending(ctx, "https://t.example", 4)
		if len(pending) != 4 || pending[0].JTI != jtis[0] || pending[3].JTI != jtis[3] {
			t.Fatalf("%s: oldest first: %v", db.name, pending)
		}
		must(t, store.Remove(ctx, "https://t.example", jtis[:7]))
		if size, _ := store.Size(ctx, "https://t.example"); size != 3 {
			t.Fatal("chunks")
		}
		must(t, store.Remove(ctx, "https://t.example", nil))
	}
}

func TestLongErrorDescriptionsAreCut(t *testing.T) {
	for _, db := range databases(t) {
		createTables(t, db.ops)
		store := sqlstore.NewPollAckStore(db.ops, prefix)
		must(t, store.Record(ctx, "https://t.example", receiver.AckError("1", receiver.InvalidRequest, strings.Repeat("x", 2000))))
		pending, _ := store.Pending(ctx, "https://t.example", 1)
		if len(pending[0].Description) != sqlstore.MaxDescriptionLength {
			t.Fatalf("%s: %d", db.name, len(pending[0].Description))
		}
	}
}

func TestAcknowledgementsAreForgottenAfterTheRetentionTime(t *testing.T) {
	for _, db := range databases(t) {
		createTables(t, db.ops)
		clock := newTestClock()
		store := sqlstore.NewPollAckStore(db.ops, prefix)
		store.Retention, store.Clock = time.Hour, clock.Now
		must(t, store.Record(ctx, "https://t.example", receiver.Ack("old")))
		clock.Advance(3601 * time.Second)
		if purged, _ := store.PurgeExpired(ctx); purged != 1 {
			t.Fatal(db.name)
		}
		if size, _ := store.Size(ctx, "https://t.example"); size != 0 {
			t.Fatal("forgotten")
		}
	}
}

func TestPurgeExpiredDeletesOnlyTheExpiredRows(t *testing.T) {
	for _, db := range databases(t) {
		createTables(t, db.ops)
		clock := newTestClock()
		store := sqlstore.NewJTIDedupStore(db.ops, prefix)
		store.Retention, store.Clock = time.Hour, clock.Now
		old := token("old")
		must(t, store.Processed(ctx, old, claimState(t, store, old)))
		clock.Advance(3000 * time.Second)
		recent := token("recent")
		must(t, store.Processed(ctx, recent, claimState(t, store, recent)))
		clock.Advance(700 * time.Second)
		if purged, _ := store.PurgeExpired(ctx); purged != 1 {
			t.Fatal(db.name)
		}
		if claimState(t, store, recent).State != receiver.Processed || !claimState(t, store, old).IsGranted() {
			t.Fatal("only the old one")
		}
	}
}

func TestCleanupPurgesAllStoresAndRunsOnlyWhenEnabled(t *testing.T) {
	for _, db := range databases(t) {
		createTables(t, db.ops)
		clock := newTestClock()
		dedup := sqlstore.NewJTIDedupStore(db.ops, prefix)
		dedup.Retention, dedup.Clock = time.Minute, clock.Now
		revocations := sqlstore.NewTokenRevocationStore(db.ops, prefix, time.Minute)
		revocations.Clock = clock.Now
		acks := sqlstore.NewPollAckStore(db.ops, prefix)
		acks.Retention, acks.Clock = time.Minute, clock.Now
		set := token("1")
		must(t, dedup.Processed(ctx, set, claimState(t, dedup, set)))
		must(t, revocations.RevokeSession(ctx, "https://idp.example", "s1"))
		must(t, acks.Record(ctx, "https://t.example", receiver.Ack("1")))
		cleanup := sqlstore.NewCleanup([]sqlstore.ExpiringStore{dedup, revocations, acks}, 20*time.Millisecond)
		if !cleanup.IsEnabled() || cleanup.PurgeExpired(ctx) != 0 {
			t.Fatal(db.name)
		}
		clock.Advance(61 * time.Second)
		cleanup.Start(ctx)
		if !cleanup.IsRunning() {
			t.Fatal("running")
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			if size, _ := acks.Size(ctx, "https://t.example"); size == 0 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("the purge")
			}
			time.Sleep(10 * time.Millisecond)
		}
		cleanup.Stop()
		if cleanup.IsRunning() {
			t.Fatal("stopped")
		}
		if !claimState(t, dedup, set).IsGranted() {
			t.Fatal("dedup purged")
		}
		if revoked, _ := revocations.IsSessionRevoked(ctx, "https://idp.example", "s1"); revoked {
			t.Fatal("revocation purged")
		}
		off := sqlstore.NewCleanup([]sqlstore.ExpiringStore{dedup}, 0)
		off.Start(ctx)
		if off.IsEnabled() || off.IsRunning() {
			t.Fatal("off")
		}
	}
}

func TestReportsDuplicateKeysMissingTablesAndOtherFailures(t *testing.T) {
	for _, db := range databases(t) {
		if exists, err := db.ops.TableExists(ctx, "EASYSSF_PROCESSED_SET"); err != nil || exists {
			t.Fatalf("%s: %v", db.name, err)
		}
		createTables(t, db.ops)
		if exists, _ := db.ops.TableExists(ctx, "EASYSSF_PROCESSED_SET"); !exists {
			t.Fatal("exists")
		}
		insert := "INSERT INTO EASYSSF_PROCESSED_SET (ISSUER, JTI, STATE, STATE_CHANGED_AT) VALUES (?, ?, ?, ?)"
		if affected, err := db.ops.Update(ctx, insert, "i", "j", "PROCESSED", int64(1)); err != nil || affected != 1 {
			t.Fatal(err)
		}
		_, err := db.ops.Update(ctx, insert, "i", "j", "PROCESSED", int64(1))
		if !sqlstore.IsDuplicateKey(err) {
			t.Fatalf("%s: %v", db.name, err)
		}
		_, err = db.ops.Update(ctx, "INSERT INTO NOWHERE (X) VALUES (?)", "x")
		var sqlError *sqlstore.Error
		if !errors.As(err, &sqlError) || sqlError.DuplicateKey {
			t.Fatalf("%s: %v", db.name, err)
		}
		if _, err := db.ops.Query(ctx, "SELECT * FROM NOWHERE", -1); err == nil {
			t.Fatal("nowhere")
		}
		if _, err := db.ops.Update(ctx, "SELECT ?"); err == nil || !strings.Contains(err.Error(), "placeholder") {
			t.Fatalf("%v", err)
		}
		rows, err := db.ops.Query(ctx, "SELECT JTI, STATE_CHANGED_AT, NULL FROM EASYSSF_PROCESSED_SET WHERE ISSUER = ?", -1, "i")
		must(t, err)
		n, ok := rows[0].Int64(1)
		if rows[0].String(0) != "j" || !ok || n != 1 || !rows[0].IsNull(2) {
			t.Fatalf("%v", rows)
		}
	}
}

func TestStoresFromConfiguration(t *testing.T) {
	for _, db := range databases(t) {
		config := receiver.DefaultConfig()
		stores := sqlstore.NewStores(db.ops, config)
		if !stores.IsEnabled() || stores.CreatesTables() != db.ops.IsEmbeddedDatabase() || len(stores.Options()) != 3 {
			t.Fatal(db.name)
		}
		config.Data.InitializeSchema = receiver.SchemaAlways
		stores = sqlstore.NewStores(db.ops, config)
		must(t, stores.PrepareTables(ctx))
		must(t, stores.PrepareTables(ctx))
		cleanup := stores.Cleanup()
		if !cleanup.IsEnabled() || cleanup.Interval() != 15*time.Minute {
			t.Fatal("cleanup")
		}
		config.Data.Enabled = false
		disabled := sqlstore.NewStores(db.ops, config)
		if disabled.Options() != nil || disabled.Cleanup().IsEnabled() || disabled.PrepareTables(ctx) != nil {
			t.Fatal("disabled")
		}
	}
}
