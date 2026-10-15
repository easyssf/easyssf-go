# easyssf-go for coding agents

Read this first, then the [README](README.md) for what the library does. This file holds what is
not obvious from the code: what the repository is, how it relates to the Java original and the
.NET and Rust ports, the conventions it follows, and the commands that matter.

## What this is

Go building blocks for the OpenID Shared Signals Framework (SSF 1.0) with CAEP, RISC and SCIM
Events (RFC 9967): a **receiver** library on `net/http`, database stores on `database/sql`, and
an in-process test transmitter. The code sits in the authentication path of its users, so
correctness of verification beats convenience everywhere. Receiver only, no transmitter.
Apache-2.0. Status: released as 0.6.0, at parity with easyssf 0.6.0 for Java; the version
follows the Java library, pre-1.0, breaking changes are acceptable when the CHANGELOG says so.
A release is a signed-off "Release X.Y.Z" commit that moves the `Unreleased` section of the
CHANGELOG under the version, and an annotated tag `vX.Y.Z` on it; the `conformance` module is
not published and gets no tag.

This is a port of [easyssf for Java](https://github.com/easyssf/easyssf), following the playbook
of [easyssf-dotnet](https://github.com/easyssf/easyssf-dotnet) and
[easyssf-rust](https://github.com/easyssf/easyssf-rust). The Java code is the reference for
protocol behaviour, names and tests; the .NET code for options and the transmitter factory; the
Rust code is the most recent port and the closest in shape, port from it when in doubt. Local
checkouts are expected at `../easyssf`, `../easyssf-dotnet` and `../easyssf-rust`. On a protocol
matter the Java code and the specification win; on a Go matter this file wins.

One Go module, `github.com/easyssf/easyssf-go`. Packages, in dependency order:

| Package | Holds | Port of | Depends on |
|---|---|---|---|
| `ssf` | The vocabulary: SETs (`EventToken`, the builder `NewSET`), subjects (`Subject`, `SubjectIdentifier`, the builders `IssSub`, `Email`, `Complex`, ...), `DeliveryMethod`, `StreamConfiguration`, `TransmitterMetadata`, over `map[string]any` | `easyssf-core` | stdlib |
| `ssf/eventtypes` | The event type URIs of SSF, CAEP, RISC and SCIM Events and the alias registry | `easyssf-core::event_types` | stdlib |
| `ssf/caep`, `ssf/risc`, `ssf/scim` | The typed events per family: kinds / operations, common and event-specific claims, the `scim` subject; `caep.NewPayload` | `easyssf-core::{caep,risc,scim}` | `ssf` |
| `ssf/signing` | `Signer`: signs the claims of `ssf.NewSET` as a SET with an RSA, ECDSA or Ed25519 key, for tests and small senders; keeps go-jose out of `ssf` | none, Go only | `ssf`, `go-jose/v4` |
| `receiver` | The receiver: verification, de-duplication, push, poll, stream management, typed handlers, revocation, session termination, metrics, `Config`, `Transmitter` and `Receiver` | `easyssf-receiver` incl. `config` and `receiver` | `ssf`, `go-jose/v4` |
| `ssftest` | `TestTransmitter`: signs SETs, serves metadata and JWK Set, issues tokens, emulates stream management and the poll endpoint, in-process over an `http.RoundTripper` | `easyssf-test` | `ssf`, `go-jose/v4` |
| `receiver/sqlstore` | The three tables shared with Java, .NET and Rust, on `database/sql`, with the `SQLite`, `PostgreSQL` and `MySQL` dialects | `easyssf-receiver-sqlx` | `receiver` |
| `conformance` (module `github.com/easyssf/easyssf-go/conformance`, `replace`d to `../`) | The OpenID conformance suite started with testcontainers-go, the receiver under test that plays the scenarios, the four plan tests (`EASYSSF_CONFORMANCE_TESTS=true`) and `cmd/cts` for manual runs | `easyssf-test-conformance`, `easyssf-receiver-spring-boot-conformance-tests` | `receiver`, `ssftest`, testcontainers-go |
| `examples/*` | The ports of the Spring Boot examples (`resource-server`, `oidc-client`, `scim-provisioning`) and the Keycloak compose setup (`keycloak/`, the same files as in the Java and Rust repositories), in the main module, not published | `examples/` | `receiver`, `ssftest` |

**No package per web framework.** `net/http` is the standard library, so `receiver.PushHandler`
is an `http.Handler` and `receiver.RevocationMiddleware` is `func(http.Handler) http.Handler`:
they mount on `net/http`, chi and gorilla/mux directly and on gin (`gin.WrapH`) and echo
(`echo.WrapHandler`) through their adapters. A framework that cannot wrap an `http.Handler`
calls `PushHandler.Handle(ctx, authorizationHeader, body)` and sends the returned status and
body, as the plain-Rust section of the Rust README describes. Session integrations
(gorilla/sessions, scs) may get sub-modules later so that their dependencies stay out of the
main module.

New protocol behaviour goes into `receiver`, new vocabulary into `ssf`, database code into
`receiver/sqlstore`.

## Build and test

```sh
go test -race ./...                      # everything, in-process, no network, no Docker
go test ./receiver -run TestRejects      # the negative verifier tests
go vet ./... && gofmt -l .               # CI fails on either
make lint                                # golangci-lint (.golangci.yml, includes staticcheck) and govulncheck; CI runs both
go run ./examples/resource-server -demo  # pushes one SET to itself through the test transmitter
EASYSSF_DATABASE_TESTS=true EASYSSF_POSTGRES_URL=postgres://... EASYSSF_MYSQL_URL=user:pw@tcp(host:3306)/db go test ./receiver/sqlstore
cd conformance && go test ./...            # the scenarios against the test transmitter, no Docker
cd conformance && EASYSSF_CONFORMANCE_TESTS=true go test -run Plan -timeout 60m -v .   # the suite in Docker, minutes per plan
```

- The tests need no network and no Docker: `ssftest.TestTransmitter` answers in-process through
  the `*http.Client` it hands out (`transmitter.Client`), whose transport routes the
  transmitter's host to its handler and refuses every other host; `ssftest.ClientFor(a, b)`
  routes to several. The sqlstore tests run on SQLite (`modernc.org/sqlite`, no cgo, one
  connection per in-memory database) and, opted in with `EASYSSF_DATABASE_TESTS=true`, on
  PostgreSQL (pgx) and MySQL (go-sql-driver); those three drivers are test dependencies only.
- Time-dependent tests use `ssftest.Eventually` and `ssftest.During` with short intervals, and a
  `Clock` moved by hand where a store measures time.
- The conformance module is a nested Go module: `go test ./...` from the root does not include
  it, CI runs its Docker-free tests separately and the `Conformance` workflow runs the plans
  nightly and on demand. Run the plans only when a change touches stream management, polling,
  verification or the harness, and say so; the suite images are pinned by digest in
  `conformance/settings.go`, the same as in the other repositories.
- `ssftest.SharedKey()` is one 2048 bit RSA key per process: generating one takes long enough that
  the tests would crawl otherwise. `ssftest.GenerateKey` always makes a fresh key, for SETs the
  receiver must reject.
- `scratch/` is ignored by git: put plans, notes and throwaway scripts there, not into the tree.
- Do not commit, push, tag or publish unless asked.

## Porting

- The Java module maps to the package, the Java package to a file of it: `org.easyssf.receiver.set`
  is `receiver/set.go` (plus `jwks.go`, `dedup.go`, `processor.go` where one file would be too
  long). Go discourages many small packages and the Java packages would form import cycles
  (`set` needs `event`, `push` needs `set`), so the receiver is one package.
- Port a Java type with its tests, the negative tests (the SET that must be rejected) before the
  positive ones, and keep the test names as sentences, `TestRejectsSETSignedWithUnknownKey` for
  `rejects_set_signed_with_unknown_key`, so that the four suites can be compared. Tests live in
  the external test package (`package receiver_test`) unless they need internals.
- The `Ssf` prefix of the Java names is the package name here: `ssf.Subject`, `receiver.Verifier`,
  `receiver.PushHandler`. `ssf.SsfSubject` would stutter, which Go style forbids, and
  `receiver.Verifier` greps as well as `SsfSetVerifier` once you know the rule. Type names
  otherwise follow Java: `JTIDedupStore`, `TokenRevocationStore`, `MetadataResolver`.
- `schema.sql` and `migration/*.sql` of `receiver/sqlstore` are copies of the Java files, byte
  for byte; CI compares them. Change them in the Java repository first.

## Code conventions

- **Raw claims are `map[string]any`** (`ssf.Claims`), decoded with `json.Decoder.UseNumber`, so
  numbers arrive as `json.Number` and the accessors (`ssf.Int64`, `ssf.StringMember`,
  `ssf.ObjectMember`) read both those and the `float64` of a plain `json.Unmarshal`. Typed
  accessors sit on top. Go maps have no order: where the Rust port keeps the order received,
  `Subject.Members` and `Context.EventTypes` iterate in alphabetical order, which is at least
  deterministic.
- **Lenient factories return nil** (`EventTokenFromClaims`, `SubjectIdentifierFrom`), no panics
  in library code for input that does not fit. Errors are typed: `*RejectedError` carries the RFC
  8935 code, `*TransmitterUnavailableError` is temporary, `ErrInProgress`, `*HandlingError`,
  `*StoreError`; callers use `errors.As`/`errors.Is`, never string matching. Enumerations the
  specification may extend (`ErrorCode`, `caep.Kind`) are open: do not switch over them
  exhaustively, implement the typed handler interfaces instead.
- **Interfaces are small and take a `context.Context` first**: `Verifier`, `JWKSetSource`,
  `JTIDedupStore`, `TokenRevocationStore`, `PollAckStore`, `SessionTerminator`, `TokenProvider`,
  `Handler`. Every interface has an in-memory implementation and, where it holds state that must
  survive a restart, a sqlstore one. The HTTP client is `*http.Client`; tests swap its transport.
- **Options structs with exported fields** (`VerifierOptions`, `ProcessorOptions`,
  `PollerOptions`), built from a `Default...()` function and read when the work is done.
  `Receiver` is built with functional options (`WithHandler`, `WithHTTPClient`, ...) over a
  `Config` that is a plain struct with `json`/`yaml`/`mapstructure` tags in kebab-case, the keys
  of the Java starter and the .NET options; `Duration` binds from `"30s"`. `Config.Validate`
  reports every failure at once with its key.
- **go-jose checks the signature only.** The header is read by hand first so that `typ`, `alg`
  and `kid` failures carry our error codes, then `jose.ParseSignedCompact` is restricted to the
  one algorithm the header names and `Verify` is given the one key selected from the JWK Set.
  Every claim rule and every error code of RFC 8935 is in `JWTVerifier.validateClaims`, because a
  SET has no `exp` and a JWT library's claim validation would reject every SET. `ES512` is
  accepted in addition to the Rust list; jsonwebtoken lacked it, go-jose has it.
- **A dropped request must not cancel the handlers.** `PushHandler.ServeHTTP` runs `Handle` with
  `context.WithoutCancel(r.Context())`; a panic in a handler is recovered by the processor,
  counted as a failed handler and becomes a 500, and the dedup store releases the claim.
- **Background work runs in goroutines bound to a context**: `Start(ctx)` returns at once,
  `Stop(ctx)` cancels and waits (`StreamRegistrar`, `Poller`, `Transmitter`, `Receiver`,
  `sqlstore.Cleanup`). Stores take a `Clock` (`func() time.Time`) the tests move by hand; no
  `time.Sleep` in tests of time-dependent behaviour.
- **Calls to the transmitter go through `exchange`/`send` in `transmitter.go`**: a per-call
  timeout from the context (`DefaultHTTPTimeout`, `easyssf.receiver.http.timeout`; a long poll
  gets its hold plus `LongPollMargin`), the `Authorizer` of the transmitter (the bearer token of
  its `TokenProvider` plus `easyssf.receiver.headers`; the endpoint is in the context,
  `EndpointOf`), retries per `RetryOptions` on connection errors and 408/429/5xx (not for poll
  requests), and one more try with a new token after a 401 when the authorizer implements
  `TokenInvalidator`. Redirects go through `URIPolicy.CheckRedirect` on a shallow copy of the
  client: same origin only (scheme, host, effective port), scheme per policy. The default client has no `Timeout` of its own, so
  that a long poll can outlast the other calls.
- **`Config.Validate` is pure.** It reports, it changes nothing: aliases are checked with
  `eventtypes.CheckAlias` and registered by `receiver.New` after the whole configuration
  passed. Keep it that way, a failed validation must not leave anything behind in the process.
- **`Transmitter` is a plain struct with exported fields** that `Receiver.New` fills from the
  configuration and `WithTransmitterCustomizer` may replace; the Rust builder and the .NET
  factory in one. `Receiver` keeps them in configuration order, `default` first.
- **Logging** is `log/slog` with attributes (`jti`, `transmitter`, `event` as alias); a nil logger
  means discard. Metrics are the `Metrics` interface under the Java names, `NoopMetrics` by
  default; an OpenTelemetry implementation is a separate package or module.
- **Protocol facts carry their source.** Doc comments cite the specification and section
  (`SSF 1.0 8.1.4.1`, `RFC 9967, section 2.4`) and name the real-world deviation they tolerate.
  Keep that habit.
- **Strict by default, lenient by configuration.** The receiver rejects what the specification
  forbids and tolerates older drafts or known transmitter quirks only behind an explicit mode
  (`ssf.Legacy`, `allow-insecure-http`).
- **Handlers are idempotent** and a SET that any handler fails on is delivered again. State that
  must survive a restart belongs in a store interface with an in-memory and a sqlstore
  implementation.
- Every exported identifier has a doc comment that starts with its name; `go vet`, `gofmt`,
  golangci-lint with `.golangci.yml` (which includes staticcheck) and govulncheck are clean. A
  `//nolint` carries its reason. No cgo.

## Where things are

The Java test classes and their Go files, so that the four suites can be compared:

| Java tests | Go file |
|---|---|
| `NimbusSsfSetVerifierTests`, `SsfTransmitterMetadataResolverTests` | `receiver/set_test.go`, `receiver/transmitter_test.go` |
| `InMemorySsfJtiDedupStoreTests`, `SsfSetProcessorTests`, `SsfPushHandlerTests` | `receiver/dedup_test.go`, `receiver/processor_test.go`, `receiver/push_test.go` |
| `SsfStreamManagementTests`, `SsfStreamVerificationTests` | `receiver/stream_test.go` |
| `SsfPollerTests`, `SsfPollerRateLimitTests` | `receiver/poll_test.go` |
| `SsfTransmittersTests`, the hosting tests of .NET | `receiver/transmitter_test.go`, `receiver/receiver_test.go` |
| `SsfSessionTerminationEventHandlerTests`, `SsfSubjectClaimsMatcherTests` | `receiver/session_test.go` |
| `SsfCaepEventHandlerTests`, `SsfRiscEventHandlerTests`, `SsfScimEventHandlerTests` | `receiver/typed_handlers_test.go`, `ssf/{caep,risc,scim}/*_test.go` |
| `AbstractJdbcSsfStoresTests`, `AbstractJdbcSharedReceiversTests` | `receiver/sqlstore/stores_test.go`, `receiver/sqlstore/shared_receivers_test.go` |
| `ConformanceSuiteModulesTests`, `ConformanceRunLocalTransmitterTests`, the four plan tests | `conformance/modules_test.go`, `conformance/run_test.go`, `conformance/plans_test.go` |

Go only, no counterpart in the other ports: `receiver.Authorizer` (every transmitter call goes
through one; `TokenProvider`s are Authorizers), `RetryOptions` for management, metadata and JWK
Set calls (the poller does not retry, it has its interval), `ssf.NewSET` and `ssf/signing`.
Subject formats that RFC 9493 dropped (`jwt_id`, `saml_assertion_id`) are not supported on
purpose: nothing in production sends them.

Not included, on purpose, as in the other ports: a transmitter, an OpenTelemetry `Metrics`
implementation (a separate module when it comes), session integrations for gorilla/sessions or
scs (`examples/oidc-client/sessions.go` shows the few lines they need).

## Documentation that changes with the code

- `README.md` is the user document. A new setting, alias, subject format or handler is documented
  there in the same change.
- `CHANGELOG.md` follows Keep a Changelog; add to the `Unreleased` section in the voice of the
  existing entries.
