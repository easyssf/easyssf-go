package sqlstore

import (
	"context"
	"embed"
	"fmt"
	"strings"
)

// The tables of the stores: their DDL, the upgrades of older releases, and the scripts that ship
// for a migration tool. The tables are those of the Java library easyssf, byte for byte: an
// application of any of the four libraries can share them.

//go:embed schema.sql migration/*.sql
var sqlFiles embed.FS

// DefaultTablePrefix is the default prefix of the table names.
const DefaultTablePrefix = "EASYSSF_"

// SchemaSQL are the statements that create the tables of this release, with the default table
// prefix, as a script: schema.sql of this package.
var SchemaSQL = mustRead("schema.sql")

// Migration is a migration script: the schema changes of one release.
type Migration struct {
	// Name is the file name, V<release>__<topic>.sql as Flyway expects it.
	Name string
	// SQL is the script, see Statements.
	SQL string
}

// Migrations are the migration scripts, oldest first: a fresh installation runs all of them, or
// SchemaSQL; an installation of an older release runs those it has not run yet.
var Migrations = []Migration{
	{Name: "V0_1_0__processed_sets_and_revocations.sql", SQL: mustRead("migration/V0_1_0__processed_sets_and_revocations.sql")},
	{Name: "V0_3_0__dedup_state_and_poll_acks.sql", SQL: mustRead("migration/V0_3_0__dedup_state_and_poll_acks.sql")},
	{Name: "V0_4_0__state_changed_at.sql", SQL: mustRead("migration/V0_4_0__state_changed_at.sql")},
}

// Where the statements and the migration scripts are, for messages.
const (
	SchemaLocation    = "schema.sql of receiver/sqlstore (sqlstore.SchemaSQL)"
	MigrationLocation = "migration/ of receiver/sqlstore (sqlstore.Migrations)"
)

func mustRead(name string) string {
	data, err := sqlFiles.ReadFile(name)
	if err != nil {
		panic(err)
	}
	return string(data)
}

// SchemaUpgrade is a column a current table has and the statement that adds it to a table of an
// older release.
type SchemaUpgrade struct {
	// Column is the name of the column.
	Column string
	// Statement is the ALTER TABLE that adds it, with a default for the rows that exist.
	Statement string
}

// ValidTablePrefix reports whether a table prefix consists of letters, digits, '_' and '.'
// only.
func ValidTablePrefix(prefix string) bool {
	for _, c := range prefix {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func prefixed(prefix, table string) string {
	if !ValidTablePrefix(prefix) {
		panic("sqlstore: the table prefix may only consist of letters, digits, '_' and '.'")
	}
	return prefix + table
}

// ProcessedSetTable is the name of the table of the JTIDedupStore. It panics if the prefix is
// not valid, see ValidTablePrefix.
func ProcessedSetTable(prefix string) string { return prefixed(prefix, "PROCESSED_SET") }

// RevocationTable is the name of the table of the TokenRevocationStore.
func RevocationTable(prefix string) string { return prefixed(prefix, "REVOCATION") }

// PollAckTable is the name of the table of the PollAckStore.
func PollAckTable(prefix string) string { return prefixed(prefix, "POLL_ACK") }

// CreateProcessedSetTable are the statements that create the table of the dedup store.
func CreateProcessedSetTable(prefix string) []string {
	table := ProcessedSetTable(prefix)
	name := strings.ReplaceAll(table, ".", "_")
	return []string{
		fmt.Sprintf("CREATE TABLE %s (\n    ISSUER VARCHAR(255) NOT NULL,\n    JTI VARCHAR(255) NOT NULL,\n    STATE VARCHAR(16) NOT NULL,\n    STATE_CHANGED_AT BIGINT NOT NULL,\n    CONSTRAINT %s_PK PRIMARY KEY (ISSUER, JTI)\n)", table, name),
		fmt.Sprintf("CREATE INDEX %s_IX1 ON %s (STATE_CHANGED_AT)", name, table),
	}
}

// ProcessedSetUpgrades are the columns later releases added to the table of the dedup store:
// STATE in 0.3.0, and STATE_CHANGED_AT in 0.4.0, which is PROCESSED_AT renamed because it records
// the claim as well as the completion.
func ProcessedSetUpgrades(prefix string) []SchemaUpgrade {
	table := ProcessedSetTable(prefix)
	return []SchemaUpgrade{
		{Column: "STATE", Statement: fmt.Sprintf("ALTER TABLE %s ADD STATE VARCHAR(16) DEFAULT 'PROCESSED' NOT NULL", table)},
		{Column: "STATE_CHANGED_AT", Statement: fmt.Sprintf("ALTER TABLE %s RENAME COLUMN PROCESSED_AT TO STATE_CHANGED_AT", table)},
	}
}

// CreateRevocationTable are the statements that create the table of the revocation store.
func CreateRevocationTable(prefix string) []string {
	table := RevocationTable(prefix)
	name := strings.ReplaceAll(table, ".", "_")
	return []string{
		fmt.Sprintf("CREATE TABLE %s (\n    KIND VARCHAR(16) NOT NULL,\n    ISSUER VARCHAR(255) NOT NULL,\n    ID VARCHAR(255) NOT NULL,\n    REVOKED_AT BIGINT NOT NULL,\n    EXPIRES_AT BIGINT NOT NULL,\n    CONSTRAINT %s_PK PRIMARY KEY (KIND, ISSUER, ID)\n)", table, name),
		fmt.Sprintf("CREATE INDEX %s_IX1 ON %s (EXPIRES_AT)", name, table),
	}
}

// CreatePollAckTable are the statements that create the table of the poll acknowledgement
// store.
func CreatePollAckTable(prefix string) []string {
	table := PollAckTable(prefix)
	name := strings.ReplaceAll(table, ".", "_")
	return []string{
		fmt.Sprintf("CREATE TABLE %s (\n    ISSUER VARCHAR(255) NOT NULL,\n    JTI VARCHAR(255) NOT NULL,\n    ERROR_CODE VARCHAR(64),\n    ERROR_DESCRIPTION VARCHAR(1024),\n    RECORDED_AT BIGINT NOT NULL,\n    CONSTRAINT %s_PK PRIMARY KEY (ISSUER, JTI)\n)", table, name),
		fmt.Sprintf("CREATE INDEX %s_IX1 ON %s (RECORDED_AT)", name, table),
	}
}

// PrepareTable makes sure a table exists and has the columns of this release. create says
// whether to create a missing table and to add missing columns to an existing one; hint is what
// else the application could do, appended to the message of the error. It fails if the table
// does not exist or lacks a column and is not to be changed; the message carries the statements
// to run.
func PrepareTable(ctx context.Context, ops *Operations, table string, createStatements []string, upgrades []SchemaUpgrade, create bool, hint string) error {
	orElse := ""
	if strings.TrimSpace(hint) != "" {
		orElse = ", " + hint
	}
	exists, err := ops.TableExists(ctx, table)
	if err != nil {
		return err
	}
	if !exists {
		if !create {
			return &Error{Message: fmt.Sprintf("The table %s of the easyssf receiver does not exist. Create it with the statements in %s%s.", table, SchemaLocation, orElse)}
		}
		for _, statement := range createStatements {
			if err := ops.Execute(ctx, statement); err != nil {
				return err
			}
		}
		return nil
	}
	missing := MissingUpgrades(ctx, ops, table, upgrades)
	if len(missing) == 0 {
		return nil
	}
	if !create {
		return &Error{Message: PredatesMessage(table, missing) + orElse + "."}
	}
	for _, upgrade := range missing {
		if err := ops.Execute(ctx, upgrade.Statement); err != nil {
			// another instance starting at the same time may have added the column
			if !columnExists(ctx, ops, table, upgrade.Column) {
				return err
			}
		}
	}
	return nil
}

// MissingUpgrades are the upgrades whose column the existing table lacks.
func MissingUpgrades(ctx context.Context, ops *Operations, table string, upgrades []SchemaUpgrade) []SchemaUpgrade {
	var missing []SchemaUpgrade
	for _, upgrade := range upgrades {
		if !columnExists(ctx, ops, table, upgrade.Column) {
			missing = append(missing, upgrade)
		}
	}
	return missing
}

// PredatesMessage is the message that a table predates this release, with the statements to
// run.
func PredatesMessage(table string, missing []SchemaUpgrade) string {
	columns := make([]string, 0, len(missing))
	statements := make([]string, 0, len(missing))
	for _, upgrade := range missing {
		columns = append(columns, upgrade.Column)
		statements = append(statements, upgrade.Statement)
	}
	return fmt.Sprintf("The table %s of the easyssf receiver predates this release and lacks the column(s) [%s]. Run [%s] or the migration scripts in %s",
		table, strings.Join(columns, ", "), strings.Join(statements, ", "), MigrationLocation)
}

// Statements splits a script (SchemaSQL, a migration) into its statements: comments removed,
// separated at ';', whitespace normalised.
func Statements(script string) []string {
	var withoutComments strings.Builder
	for _, line := range strings.Split(script, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		withoutComments.WriteString(line)
		withoutComments.WriteString("\n")
	}
	var statements []string
	for _, statement := range strings.Split(withoutComments.String(), ";") {
		normalised := strings.Join(strings.Fields(statement), " ")
		if normalised != "" {
			statements = append(statements, normalised)
		}
	}
	return statements
}

func columnExists(ctx context.Context, ops *Operations, table, column string) bool {
	_, err := ops.Query(ctx, fmt.Sprintf("SELECT %s FROM %s WHERE 1 = 0", column, table), 1)
	return err == nil
}
