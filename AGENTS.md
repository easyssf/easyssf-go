# easyssf-go for coding agents

Read this first, then the [README](README.md) for what the library does. This file holds what is
not obvious from the code: what the repository is, how it relates to the Java original and the
.NET and Rust ports, the conventions it follows, and the commands that matter.

## What this is

Go building blocks for the OpenID Shared Signals Framework (SSF 1.0) with CAEP, RISC and SCIM
Events (RFC 9967): a **receiver** library on `net/http`, database stores on `database/sql` (to
come), and an in-process test transmitter. The code sits in the authentication path of its
users, so correctness of verification beats convenience everywhere. Receiver only, no
transmitter. Apache-2.0. Status: **a sketch**, pre-1.0; the version will follow the Java library
(`0.7.0-alpha.N`), breaking changes are acceptable when the CHANGELOG says so.

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
| `ssf` | The vocabulary: SETs (`EventToken`), subjects (`Subject`, `SubjectIdentifier`, the builders `IssSub`, `Email`, `Complex`, ...), `DeliveryMethod`, `StreamConfiguration`, `TransmitterMetadata`, over `map[string]any` | `easyssf-core` | stdlib |
| `ssf/eventtypes` | The event type URIs of SSF, CAEP, RISC and SCIM Events and the alias registry | `easyssf-core::event_types` | stdlib |
| `ssf/caep`, `ssf/risc`, `ssf/scim` | The typed events per family (`caep` is sketched, `risc` and `scim` are stubs) | `easyssf-core::{caep,risc,scim}` | `ssf` |
| `receiver` | The receiver: verification, de-duplication, push, poll, stream management, handlers, revocation, session termination, metrics, `Config` and `Receiver` | `easyssf-receiver` incl. `config` and `receiver` | `ssf`, `go-jose/v4` |
| `ssftest` | `TestTransmitter`: signs SETs, serves metadata and JWK Set, in-process over an `http.RoundTripper` | `easyssf-test` | `ssf`, `go-jose/v4` |
| `receiver/sqlstore` (to come) | The three tables shared with Java, .NET and Rust, on `database/sql` | `easyssf-receiver-sqlx` | `receiver` |
| `examples/*` | The port of the Spring Boot examples, not published; `resource-server` exists | `examples/` | `receiver`, `ssftest` |

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
staticcheck ./...                        # CI runs it; go install honnef.co/go/tools/cmd/staticcheck@latest
go run ./examples/resource-server -demo  # pushes one SET to itself through the test transmitter
```

- The tests need no network and no Docker: `ssftest.TestTransmitter` answers in-process through
  the `*http.Client` it hands out (`transmitter.Client`), whose transport routes the
  transmitter's host to its handler and refuses every other host. The sqlstore tests will run
  on SQLite (`modernc.org/sqlite`, no cgo) and, opted in with `EASYSSF_DATABASE_TESTS=true`, on
  PostgreSQL and MySQL.
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
- `schema.sql` and `migration/*.sql` of `receiver/sqlstore` will be copies of the Java files,
  byte for byte; CI compares them. Change them in the Java repository first.

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
  `Stop(ctx)` cancels and waits. Stores take a `Clock` (`func() time.Time`) the tests move by
  hand; no `time.Sleep` in tests of time-dependent behaviour.
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
- Every exported identifier has a doc comment that starts with its name; `go vet`, `gofmt` and
  `staticcheck` are clean. No cgo.

## What the sketch has and what is left

Done and tested: `ssf` (token, subjects, delivery, stream, metadata), `ssf/eventtypes`,
`receiver` verification (`JWTVerifier`, `HTTPJWKSetSource` with cache and rate-limited refresh,
`IssuerRoutingVerifier`, `MetadataResolver` with `URIPolicy` and the two well-known locations),
`InMemoryJTIDedupStore` with lease and renewal, `Processor` with claim renewal, critical subject
members and panic recovery, `PushHandler` as `http.Handler` and by issuer, `Context`/`Handler`/
`ForEvent`, `TokenRevocationStore` with the in-memory store, handler and middleware,
`SessionTerminator` and its handler, `Config` with defaults and validation, `Receiver` assembly
from configuration, `ssftest.TestTransmitter` for metadata, JWK Set and signing.

Left, each marked `SKETCH` in the code, in the order that unblocks the most:

1. `receiver/stream.go`: `StreamClient` bodies, `StreamRegistrar` (reuse/update/create with
   retries, audience and poll endpoint from the registered stream, delete on shutdown),
   `StreamVerification` with `InvalidState`. Tests: `stream_management.rs`, `stream_verification.rs`.
2. `receiver/poll.go`: `Poller.PollOnce` and the loop (RFC 8936 request body with `maxEvents`,
   `returnImmediately`, `ack`, `setErrs`; `Retry-After`; long polling with a longer timeout),
   `ClientCredentialsTokenProvider` in `transmitter.go`. Tests: `poller.rs`, `transmitters.rs`.
3. `ssftest`: the token, stream management, poll and verification endpoints of the transmitter,
   `QueueSet`, `AcknowledgedSets`, `ReportedErrors`, `Streams`.
4. `receiver.go`: build registrar and poller per transmitter, `Health` from their states, the
   per-transmitter `ExpectedAuthHeader` already routes.
5. `ssf/caep` accessors, `ssf/risc`, `ssf/scim`; the typed handler interfaces
   (`CaepHandler`, `RiscHandler`, `ScimHandler`) and their adapters in `receiver`.
6. `receiver/sqlstore`: the three stores over `database/sql` with the Java schema and migrations,
   `?` placeholders rewritten for PostgreSQL, the cleanup goroutine.
7. The remaining examples (OIDC client, SCIM provisioning) and the Keycloak compose pointer.

## Documentation that changes with the code

- `README.md` is the user document. A new setting, alias, subject format or handler is documented
  there in the same change.
- `CHANGELOG.md` follows Keep a Changelog; add to the `Unreleased` section in the voice of the
  existing entries.
