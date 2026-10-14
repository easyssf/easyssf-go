// Package sqlstore holds the database stores of the easyssf receiver on database/sql: processed
// SETs, revocations and the acknowledgements a poller owes, in the three tables the Java, .NET
// and Rust libraries use (EASYSSF_PROCESSED_SET, EASYSSF_REVOCATION, EASYSSF_POLL_ACK), so that
// applications of any of the four can share one database. A port of easyssf-receiver-jdbc of
// the Java library and of easyssf-receiver-sqlx of the Rust port.
//
// The stores are plain SQL: ? placeholders in the order of the arguments, VARCHAR and BIGINT,
// timestamps as milliseconds since the epoch, no vendor syntax; a result limit is applied by
// reading no further, never with LIMIT. The Dialect rewrites the placeholders for PostgreSQL,
// which database/sql does not do, and tells a duplicate key from other failures. SQLite
// (modernc.org/sqlite, no cgo), PostgreSQL (pgx stdlib) and MySQL (go-sql-driver) are known;
// another database gets a Dialect of its own.
//
//	ops := sqlstore.NewOperations(db, sqlstore.PostgreSQL)
//	stores := sqlstore.NewStores(ops, config)
//	if err := stores.PrepareTables(ctx); err != nil { ... }   // checks or creates the tables, per easyssf.receiver.data
//	cleanup := stores.Cleanup()                               // purges expired rows every data.cleanup-interval
//	cleanup.Start(ctx)
//	rcv, err := receiver.New(config, stores.Options()...)
package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// DB is what the stores run their statements on: an *sql.DB, or an *sql.Conn or *sql.Tx when
// the application wants its own transaction around a store call. PrepareTables wants an *sql.DB:
// its column checks are statements that fail on purpose, which aborts a PostgreSQL transaction.
type DB interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// Dialect is what differs between databases: how positional placeholders are written, how a
// duplicate key and a missing table are recognised, and whether the database is an embedded
// one whose tables an application creates itself.
type Dialect struct {
	// Name is the name of the database, for messages.
	Name string
	// Placeholder is the placeholder of the n-th argument (1-based): "?" or "$n".
	Placeholder func(n int) string
	// IsDuplicateKey reports whether an error of the driver says that an insert violated a
	// unique constraint.
	IsDuplicateKey func(error) bool
	// IsMissingTable reports whether an error of the driver says that a table does not exist
	// (or the statement was not understood otherwise).
	IsMissingTable func(error) bool
	// Embedded says whether the database is an embedded one (SQLite), which an application
	// creates the tables in without a migration tool.
	Embedded bool
}

func questionMark(int) string { return "?" }

func dollar(n int) string { return "$" + strconv.Itoa(n) }

// sqlState is implemented by the errors of pgx (PgError) and others that carry a SQLSTATE.
type sqlState interface{ SQLState() string }

func stateOf(err error) string {
	var withState sqlState
	if errors.As(err, &withState) {
		return withState.SQLState()
	}
	// go-sql-driver/mysql renders "Error 1062 (23000): Duplicate entry"
	message := err.Error()
	if start := strings.Index(message, " ("); start > 0 && len(message) > start+8 && message[start+7] == ')' {
		return message[start+2 : start+7]
	}
	return ""
}

func duplicateByStateOrMessage(err error) bool {
	if strings.HasPrefix(stateOf(err), "23") {
		return true
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "unique constraint") || strings.Contains(message, "duplicate key") ||
		strings.Contains(message, "duplicate entry") || strings.Contains(message, "constraint failed")
}

// badGrammarClasses are the SQLSTATE classes of a statement the database did not understand,
// among them a missing table: standard class 42, and the classes some databases use instead.
var badGrammarClasses = []string{"07", "21", "2A", "37", "42", "65", "S0"}

func missingByStateOrMessage(err error) bool {
	if state := stateOf(err); len(state) >= 2 {
		for _, class := range badGrammarClasses {
			if strings.HasPrefix(state, class) {
				return true
			}
		}
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "no such table") || strings.Contains(message, "does not exist") ||
		strings.Contains(message, "doesn't exist") || strings.Contains(message, "no such column") || strings.Contains(message, "unknown column")
}

// The known dialects.
var (
	// SQLite is modernc.org/sqlite (and mattn/go-sqlite3): ? placeholders, embedded.
	SQLite = Dialect{Name: "sqlite", Placeholder: questionMark, IsDuplicateKey: duplicateByStateOrMessage, IsMissingTable: missingByStateOrMessage, Embedded: true}
	// PostgreSQL is pgx (stdlib) and lib/pq: $1, $2, ... placeholders.
	PostgreSQL = Dialect{Name: "postgres", Placeholder: dollar, IsDuplicateKey: duplicateByStateOrMessage, IsMissingTable: missingByStateOrMessage}
	// MySQL is go-sql-driver/mysql, for MySQL and MariaDB: ? placeholders.
	MySQL = Dialect{Name: "mysql", Placeholder: questionMark, IsDuplicateKey: duplicateByStateOrMessage, IsMissingTable: missingByStateOrMessage}
)

// DialectFor is the dialect for a driver name as given to sql.Open (sqlite, sqlite3, pgx,
// postgres, mysql); ok is false for an unknown driver.
func DialectFor(driverName string) (dialect Dialect, ok bool) {
	switch strings.ToLower(driverName) {
	case "sqlite", "sqlite3":
		return SQLite, true
	case "pgx", "postgres", "postgresql":
		return PostgreSQL, true
	case "mysql", "mariadb":
		return MySQL, true
	}
	return Dialect{}, false
}

// Error says that a statement of a store failed.
type Error struct {
	// SQL is the statement.
	SQL string
	// Message says what went wrong.
	Message string
	// DuplicateKey says that an insert violated a unique constraint: the row exists already.
	DuplicateKey bool
	// Cause is the error of the driver, if any.
	Cause error
}

func (e *Error) Error() string {
	if e.DuplicateKey {
		return "duplicate key: " + e.SQL
	}
	if e.SQL == "" {
		return e.Message
	}
	return fmt.Sprintf("could not run %s: %s", e.SQL, e.Message)
}

// Unwrap is the cause.
func (e *Error) Unwrap() error { return e.Cause }

// IsDuplicateKey reports whether err says that an insert violated a unique constraint.
func IsDuplicateKey(err error) bool {
	var sqlError *Error
	return errors.As(err, &sqlError) && sqlError.DuplicateKey
}

// Row is a row of a query result, its columns in the order of the query.
type Row []any

// String is the string of a column, "" if NULL. A number is rendered as text.
func (r Row) String(index int) string {
	if index >= len(r) {
		return ""
	}
	switch v := r[index].(type) {
	case nil:
		return ""
	case string:
		return v
	case []byte:
		return string(v)
	case int64:
		return strconv.FormatInt(v, 10)
	default:
		return fmt.Sprint(v)
	}
}

// Int64 is the integer of a column; ok is false if NULL. A numeric string is parsed, as some
// drivers return BIGINT that way.
func (r Row) Int64(index int) (n int64, ok bool) {
	if index >= len(r) {
		return 0, false
	}
	switch v := r[index].(type) {
	case int64:
		return v, true
	case int32:
		return int64(v), true
	case int:
		return int64(v), true
	case float64:
		return int64(v), true
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		return n, err == nil
	case []byte:
		n, err := strconv.ParseInt(strings.TrimSpace(string(v)), 10, 64)
		return n, err == nil
	}
	return 0, false
}

// IsNull reports whether a column is NULL.
func (r Row) IsNull(index int) bool { return index >= len(r) || r[index] == nil }

// Operations runs the SQL of the stores on a DB with a Dialect: the SsfJdbcOperations of the
// Java library.
type Operations struct {
	db      DB
	dialect Dialect
}

// NewOperations runs the statements on db with the dialect.
func NewOperations(db DB, dialect Dialect) *Operations {
	if dialect.Placeholder == nil {
		dialect.Placeholder = questionMark
	}
	if dialect.IsDuplicateKey == nil {
		dialect.IsDuplicateKey = duplicateByStateOrMessage
	}
	if dialect.IsMissingTable == nil {
		dialect.IsMissingTable = missingByStateOrMessage
	}
	return &Operations{db: db, dialect: dialect}
}

// Dialect is the dialect of the database.
func (o *Operations) Dialect() Dialect { return o.dialect }

// DB is the database the statements run on.
func (o *Operations) DB() DB { return o.db }

// IsEmbeddedDatabase reports whether the database is an embedded one (SQLite).
func (o *Operations) IsEmbeddedDatabase() bool { return o.dialect.Embedded }

// Placeholders rewrites the ? placeholders of a statement for the dialect, checking that their
// number matches the arguments.
func Placeholders(sql string, arguments int, dialect Dialect) (string, error) {
	count := strings.Count(sql, "?")
	if count != arguments {
		return "", &Error{SQL: sql, Message: fmt.Sprintf("the statement has %d placeholder(s) but %d argument(s)", count, arguments)}
	}
	if dialect.Placeholder == nil || dialect.Placeholder(1) == "?" {
		return sql, nil
	}
	var rewritten strings.Builder
	index := 0
	for _, c := range sql {
		if c == '?' {
			index++
			rewritten.WriteString(dialect.Placeholder(index))
		} else {
			rewritten.WriteRune(c)
		}
	}
	return rewritten.String(), nil
}

func (o *Operations) translate(sql string, err error) error {
	if err == nil {
		return nil
	}
	if o.dialect.IsDuplicateKey(err) {
		return &Error{SQL: sql, Message: err.Error(), DuplicateKey: true, Cause: err}
	}
	return &Error{SQL: sql, Message: err.Error(), Cause: err}
}

// Update runs an insert, update or delete and returns the number of rows affected. An Error
// with DuplicateKey says the statement violated a unique constraint.
func (o *Operations) Update(ctx context.Context, sql string, args ...any) (int64, error) {
	rewritten, err := Placeholders(sql, len(args), o.dialect)
	if err != nil {
		return 0, err
	}
	result, err := o.db.ExecContext(ctx, rewritten, args...)
	if err != nil {
		return 0, o.translate(sql, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, o.translate(sql, err)
	}
	return affected, nil
}

// Query runs a query and returns at most maxRows rows (all if maxRows is negative). The limit is
// applied by reading no further, which every driver supports, rather than with the SQL for it,
// which differs between databases (FETCH FIRST, LIMIT, TOP).
func (o *Operations) Query(ctx context.Context, sql string, maxRows int, args ...any) ([]Row, error) {
	rewritten, err := Placeholders(sql, len(args), o.dialect)
	if err != nil {
		return nil, err
	}
	rows, err := o.db.QueryContext(ctx, rewritten, args...)
	if err != nil {
		return nil, o.translate(sql, err)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return nil, o.translate(sql, err)
	}
	var result []Row
	for (maxRows < 0 || len(result) < maxRows) && rows.Next() {
		row := make(Row, len(columns))
		pointers := make([]any, len(columns))
		for i := range row {
			pointers[i] = &row[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			return nil, o.translate(sql, err)
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, o.translate(sql, err)
	}
	return result, nil
}

// Execute runs a statement that returns nothing, for example DDL.
func (o *Operations) Execute(ctx context.Context, sql string) error {
	_, err := o.db.ExecContext(ctx, sql)
	return o.translate(sql, err)
}

// TableExists reports whether the table exists.
func (o *Operations) TableExists(ctx context.Context, table string) (bool, error) {
	_, err := o.Query(ctx, "SELECT COUNT(*) FROM "+table+" WHERE 1 = 0", 1)
	if err == nil {
		return true, nil
	}
	var sqlError *Error
	if errors.As(err, &sqlError) && sqlError.Cause != nil && o.dialect.IsMissingTable(sqlError.Cause) {
		return false, nil
	}
	return false, err
}

func millis(t time.Time) int64 { return t.UnixMilli() }

func fromMillis(ms int64) time.Time { return time.UnixMilli(ms).UTC() }
