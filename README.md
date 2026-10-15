# easyssf-go

Building blocks for the
[OpenID Shared Signals Framework (SSF)](https://openid.net/specs/openid-sharedsignals-framework-1_0.html)
in Go, for applications that receive security events: a **receiver** library on `net/http` that
mounts on any Go web framework, an in-process **test transmitter**, and database stores on
`database/sql`. A port of [easyssf for Java](https://github.com/easyssf/easyssf), following the
layout of [easyssf-dotnet](https://github.com/easyssf/easyssf-dotnet) and
[easyssf-rust](https://github.com/easyssf/easyssf-rust); the four share their test suites, their
database tables and their configuration keys.

**Turn a Go application into an SSF receiver without implementing SET validation, metadata
discovery, PUSH and POLL delivery, stream management and replay protection yourself.** Reacting to
a security event is a function:

```go
rcv, err := receiver.New(config,
    receiver.WithHandler(receiver.ForEventFunc("CaepSessionRevoked",
        func(ctx context.Context, event *receiver.Context) error {
            subject := event.Subject()
            // end what you hold for subject.SessionID() or subject.Sub()
            return nil
        })))
if err != nil {
    log.Fatal(err)                                    // every configuration failure at once
}
rcv.Start(ctx)                                        // registers the stream, starts polling
mux.Handle("POST "+rcv.PushEndpointPath(), rcv.PushHandler()) // POST /ssf/push
```

| | |
|---|---|
| **Status** | 0.6.0, at feature parity with [easyssf 0.6.0 for Java](https://github.com/easyssf/easyssf); the version follows the Java library. Pre-1.0: breaking changes are acceptable when the CHANGELOG says so |
| **Go** | 1.25 or later, no cgo |
| **Dependencies** | `github.com/go-jose/go-jose/v4` for JWS and JWK; `modernc.org/sqlite`, `pgx` and `go-sql-driver/mysql` only for the tests of `receiver/sqlstore`; everything else is the standard library |
| **License** | Apache-2.0 |

## Packages

| Package | Holds |
|---|---|
| `ssf` | The vocabulary: SETs, subjects, delivery methods, stream configuration, transmitter metadata, the SET builder; `ssf/eventtypes` the event type URIs with aliases; `ssf/caep`, `ssf/risc`, `ssf/scim` the typed events; `ssf/signing` signs SETs |
| `receiver` | The receiver: verification, de-duplication with a lease, push and poll, stream management, typed handlers, token revocation, session termination, metrics; `Config` and `Receiver`, which assembles a receiver from it; `PushHandler` (an `http.Handler`) and `RevocationMiddleware` |
| `receiver/sqlstore` | The three tables shared with Java, .NET and Rust, on `database/sql`: SQLite, PostgreSQL and MySQL |
| `ssftest` | `TestTransmitter`: signs SETs, serves metadata and the JWK Set, issues tokens, emulates stream management and the poll endpoint, in-process through an `*http.Client` it hands out, no socket involved |
| `conformance` (own module) | Runs the OpenID conformance suite's SSF receiver test plans against the receiver, with the suite started by testcontainers-go, see [Conformance](#conformance) |

There is no package per web framework: `PushHandler` is an `http.Handler`, so it mounts on
`net/http`, chi and gorilla/mux as it is, and on gin and echo through `gin.WrapH` and
`echo.WrapHandler`. Anything else calls `PushHandler.Handle(ctx, authorizationHeader, body)` and
sends the status and body it returns (see [Any framework](#any-framework)).

## What it does

- **Verifies a SET** (RFC 8417): signature against the transmitter's JWK Set, `typ`, `iss`, `aud`,
  `jti`, `iat`, `events` and the top-level `sub_id` SSF 1.0 requires. Rejections carry the error
  codes of RFC 8935 (`invalid_request`, `invalid_key`, `invalid_issuer`, `invalid_audience`).
  go-jose checks the signature only; every claim rule is the library's, because a SET has no
  `exp` and a JWT library's claim validation would reject every SET.
- **Caches the JWK Set** and fetches it again when a SET names a key it does not know, rate
  limited so that bogus SETs cannot make the receiver flood the transmitter.
- Accepts only asymmetric signature algorithms (`RS256` by default) and RSA keys of at least 2048
  bits.
- Resolves **subjects** (RFC 9493): every simple format, complex subjects, aliases, the `scim`
  format, and the conventions of early SSF drafts and of Keycloak behind explicit modes.
- Knows the **event types** of SSF, CAEP, RISC and SCIM Events (RFC 9967) by URI and by alias
  (`CaepSessionRevoked`), and lets you register aliases for vendor specific types. The **typed
  handlers** `CaepHandler`, `RiscHandler` and `ScimHandler` dispatch by kind with typed access
  to the payload (`event.CredentialType()`, `event.Reason()`, `event.Data()`).
- **Receives pushed SETs** (RFC 8935): checks the transmitter's `Authorization` header in constant
  time, verifies, **skips SETs it has already processed** (`jti` de-duplication with a lease and
  claim renewal, so a SET another instance is handling is left alone and one abandoned by a crash
  is taken over), hands verified events to the handlers, answers `202`, `400` with an error
  document, `401`, `413`, `500` or `503`. The handlers run detached from the request context and a
  panic in one is a failed handler, so a transmitter that disconnects does not cancel them.
- **Polls for SETs** (RFC 8936): short or long polling, acknowledgements and error reports ride on
  the next request and wait in a `PollAckStore` until it succeeded, invalid SETs are reported with
  their error code, `Retry-After` and `429` are honoured, the acknowledgements owed are flushed on
  shutdown.
- **Discovers the transmitter** from its `.well-known/ssf-configuration`, at the SSF location and
  at the one OpenID providers tend to use, and holds its issuer and endpoints to `https` unless a
  loopback address or `allow-insecure-http` says otherwise.
- **Manages its stream** (SSF 1.0, section 8.1): looks a stream up by id, or reuses, updates or
  creates the stream it wants, in the background with retries, learns the audience of the SETs
  and the poll endpoint from it, refuses a stream the transmitter created with another issuer,
  validates **verification events** by stream and state, and deletes the stream on shutdown when
  asked. The management and poll endpoints are called with a fixed token or one obtained with the
  **client credentials grant**, renewed ahead of its expiry and after a `401`.
- **Revokes access tokens and sessions**: `session-revoked` events fill a `TokenRevocationStore`;
  `RevocationMiddleware` rejects tokens with that `sid` or that `sub` issued up to the event. A
  `SessionTerminator` ends server-side sessions as the event arrives; `SubjectMatches` tells which
  sessions belong to the subject of an event, `scim` subjects included.
- **Shares its state between instances** with `receiver/sqlstore`: processed SETs, revocations
  and the acknowledgements owed in the tables of the Java library, so that a SET pushed to one
  instance is handled once and acknowledged by whichever instance polls next.
- Records **metrics** through the `Metrics` interface under the Java names and reports its
  **health** per transmitter: metadata resolved, stream registered, last poll.

## Getting started

```sh
go get github.com/easyssf/easyssf-go
```

The configuration keys are those of the Spring Boot starter and the .NET options, in kebab-case,
under `easyssf.receiver`; `receiver.Config` carries `json`, `yaml` and `mapstructure` tags, so
bind it with `encoding/json`, `yaml.v3`, koanf or viper over `receiver.DefaultConfig()`:

```yaml
easyssf:
  receiver:
    transmitter-issuer: https://idp.example/realms/demo   # required
    expected-audience: https://my-app.example             # or let the receiver register the stream
    push:
      expected-auth-header: "Bearer ${SSF_PUSH_SECRET}"   # recommended
```

```go
config := receiver.DefaultConfig()
if err := yaml.Unmarshal(bytes, &wrapper{EasySSF: struct{ Receiver *receiver.Config }{&config}}); err != nil { ... }

rcv, err := receiver.New(config,
    receiver.WithLogger(slog.Default()),
    receiver.WithHandler(receiver.ForEventFunc("CaepCredentialChange", credentialsChanged)))
if err != nil { ... }                                   // the configuration is validated, every failure at once
rcv.Start(ctx)                                          // registers the stream, starts polling
defer rcv.Stop(context.Background())                    // sends the acknowledgements it owes

mux := http.NewServeMux()
mux.Handle("POST "+rcv.PushEndpointPath(), rcv.PushHandler())
// after the middleware that validates the access token and leaves its claims on the request
revoked := receiver.RevocationMiddleware(rcv.TokenRevocationStore(), func(r *http.Request) (receiver.TokenClaims, bool) {
    claims, ok := r.Context().Value(jwtClaimsKey).(MyClaims)
    return receiver.TokenClaims{Issuer: claims.Iss, Subject: claims.Sub, SessionID: claims.Sid, IssuedAt: claims.Iat}, ok
})
mux.Handle("GET /api/orders", revoked(orders))
mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(rcv.Health(r.Context())) })
```

To poll instead of being pushed to, and to let the receiver register its own stream:

```yaml
easyssf:
  receiver:
    transmitter-issuer: https://idp.example/realms/demo
    delivery-method: poll
    stream:
      management: receiver
      events-requested: [CaepSessionRevoked, CaepCredentialChange]
    poll:
      long-polling: true
    oauth2:
      token-uri: https://idp.example/realms/demo/protocol/openid-connect/token
      client-id: my-app
      client-secret: "..."
```

The audience of the stream is learned from the registration, so `expected-audience` is not needed;
until the stream is registered, SETs are left for redelivery (`503`). Several transmitters go under
`easyssf.receiver.transmitters.<name>`, each with the same settings; the one at `easyssf.receiver`
is named `default`, and the push endpoint authenticates each by its own header.
`receiver.WithTransmitterCustomizer` replaces parts of any transmitter before it is assembled.

Every setting, with its default, is documented on `receiver.Config` and its sub-structs
(`go doc ./receiver Config`); the keys are those of the
[.NET configuration table](https://github.com/easyssf/easyssf-dotnet#configuration) in
kebab-case, with durations as strings such as `"30s"` or `"24h"`. The HTTP timeout of
`easyssf.receiver.http.timeout` applies per call, so that a long poll can wait longer; the default
client has no `Timeout` of its own, and one given with `WithHTTPClient` caps every call.

A management, metadata or JWK Set call that fails with a connection error or a `408`, `429`,
`500`, `502`, `503` or `504` is tried again, twice by default, after a quarter of a second
doubling up to five seconds or the `Retry-After` the transmitter sends
(`easyssf.receiver.http.retry.max-retries`, `initial-backoff`, `max-backoff`; `max-retries: 0`
turns it off). Poll requests are not retried: the poller has its interval and pauses on
`Retry-After`. The stream registrar keeps retrying a failed registration regardless.

Every endpoint of a transmitter, configured or taken from its metadata or stream, must use
`https`, or `http` on loopback (`allow-insecure-http` lifts that, for development only). A
redirect is followed only within the origin of the request, the same scheme, host and port, and
only to a scheme the policy allows, whatever the `http.Client` passed in would do: an `https`
endpoint cannot send the receiver's token to `http`, to another host or to another port.

Every call to a transmitter goes through a `receiver.Authorizer`: the bearer token of its
`TokenProvider`, and the headers of `easyssf.receiver.headers` (an API key, a tenant), which are
sent with every call including those for metadata and keys. For headers on particular endpoints
only, or anything else a transmitter wants, compose `receiver.StaticHeaders`,
`receiver.EndpointHeaders` and your own `receiver.AuthorizerFunc` (the endpoint a request is for
is `receiver.EndpointOf(ctx)`) with `receiver.Authorizers` and give the result to
`receiver.NewStreamClient` and `receiver.NewPoller` in a `WithTransmitterCustomizer`.

### chi, gorilla/mux, gin, echo

```go
r.Method(http.MethodPost, rcv.PushEndpointPath(), rcv.PushHandler())   // chi
r.Handle(rcv.PushEndpointPath(), rcv.PushHandler()).Methods("POST")    // gorilla/mux
g.POST(rcv.PushEndpointPath(), gin.WrapH(rcv.PushHandler()))           // gin
e.POST(rcv.PushEndpointPath(), echo.WrapHandler(rcv.PushHandler()))    // echo
```

The revocation middleware is `func(http.Handler) http.Handler`, which chi and gorilla take as
they are and gin and echo through their adapters.

### Any framework

`PushHandler.Handle(ctx, authorizationHeader, body)` returns a status and an optional JSON body.
Give it a context that outlives the request so that a transmitter that disconnects does not cancel
the handlers:

```go
response := rcv.PushHandler().Handle(context.WithoutCancel(reqCtx), authorization, body)
// send response.Status and, if not nil, response.Body as application/json with Content-Language: en
```

Assembling the parts by hand reads like the plain Java section of the Java README: a `Verifier`
over a `JWKSetSource`, a `Processor` with a `JTIDedupStore` and handlers, a `PushHandler` over
the processor, a `StreamClient` with a `StreamRegistrar`, a `Poller`; see
`receiver/processor_test.go`, `receiver/stream_test.go` and `receiver/poll_test.go`.

### Typed handlers

```go
type stepUp struct{ receiver.NoopCaepHandler }

func (stepUp) OnAssuranceLevelChange(ctx context.Context, event *caep.Event, context *receiver.Context) error {
    if event.ChangeDirection() == "decrease" {
        // require a step-up for context.Subject().Sub() to event.CurrentLevel()
    }
    return nil
}

rcv, err := receiver.New(config, receiver.WithHandler(receiver.Caep(stepUp{})))
```

`receiver.Risc` and `receiver.Scim` do the same for RISC 1.0 and SCIM Events; a handler that also
implements `OnCaepEvent` (`OnRiscEvent`, `OnScimEvent`) sees every event of its family first and
dispatches with `receiver.DispatchCaepEvent` when it wants to.

### Ending sessions

An application whose sessions are not access tokens (an OIDC client with a session cookie) gives
the receiver a `SessionTerminator` over its session store; `receiver.SubjectMatches` compares the
subject of an event with the claims of the ID token a user logged in with:

```go
func (s *sessions) TerminateSessions(ctx context.Context, subject *ssf.Subject) (int, error) {
    ended := 0
    for id, session := range s.all() {
        if receiver.SubjectMatches(subject, session.IDTokenClaims, session.Username) {
            s.end(id)
            ended++
        }
    }
    return ended, nil
}

rcv, err := receiver.New(config, receiver.WithSessionTerminator(sessions))
```

`easyssf.receiver.session-termination` says which events end which sessions (`CaepSessionRevoked`
ends the session named, `CaepCredentialChange` all sessions of the user) and how a `scim` subject
is matched (`externalId` and `id` with `sub`, `userName` with `preferred_username` by default).

### Sharing state between instances

A SET is pushed to one instance of an application. `receiver/sqlstore` keeps the processed SETs,
the revocations and the acknowledgements a poller owes in the database of the application, in the
tables of the Java library (`EASYSSF_PROCESSED_SET`, `EASYSSF_REVOCATION`, `EASYSSF_POLL_ACK`):

```go
db, err := sql.Open("pgx", databaseURL)
stores := sqlstore.NewStores(sqlstore.NewOperations(db, sqlstore.PostgreSQL), config)
if err := stores.PrepareTables(ctx); err != nil { ... }   // checks or creates the tables, per easyssf.receiver.data
cleanup := stores.Cleanup()                               // purges expired rows every data.cleanup-interval
cleanup.Start(ctx)
rcv, err := receiver.New(config, append(stores.Options(), receiver.WithHandler(...))...)
```

`sqlstore.SQLite` (modernc.org/sqlite, no cgo), `sqlstore.PostgreSQL` (pgx) and `sqlstore.MySQL`
(go-sql-driver) are the known dialects, `sqlstore.DialectFor(driverName)` picks one; the statements
are plain SQL with `?` placeholders, rewritten to `$n` for PostgreSQL. `schema.sql` and
`migration/*.sql` of the package are the files of the Java library byte for byte, for Flyway or
Liquibase; `initialize-schema: always` lets the stores create and upgrade the tables themselves.
On another store, implement `JTIDedupStore`, `TokenRevocationStore` and `PollAckStore` and give
them to `receiver.New` with `WithDedupStore`, `WithTokenRevocationStore` and `WithPollAckStore`.

## Testing your receiver

`ssftest.TestTransmitter` signs SETs, serves its metadata and JWK Set, hands out access tokens and
emulates the stream management and poll endpoints, all in-process through the `*http.Client` it
hands out: give it to the receiver as its HTTP client, no socket is involved.

```go
transmitter := ssftest.New()
rcv, err := receiver.New(configFor(transmitter.Issuer()), receiver.WithHTTPClient(transmitter.Client))
set := transmitter.Set("CaepSessionRevoked", ssf.Complex(ssf.IssSub(transmitter.Issuer(), "alice"), ssf.Opaque("session-1")))
// POST set to /ssf/push, or transmitter.QueueSet(set) for a polling receiver
ssftest.Eventually(t, 5*time.Second, "the acknowledgement", func() bool { return len(transmitter.AcknowledgedSets()) == 1 })
```

`transmitter.SetAvailable(false)` simulates an outage, `transmitter.ExpireAccessTokens()` a
rejected token, `transmitter.SetLongPollHold(d)` a transmitter that holds long polls,
`ssftest.ClientFor(a, b)` routes to several transmitters, `ssftest.GenerateKey(1024, "weak")` makes
keys a receiver has to reject, `ssftest.Sign` and `ssftest.SignWith` sign claims with any key and
algorithm, `ssftest.Unsigned` makes an `alg: none` token.

A SET of your own is built with `ssf.NewSET` and signed with `ssf/signing`, which the test
transmitter uses too (`transmitter.Signer()`):

```go
claims, err := ssf.NewSET(issuer).Audience("https://app.example").
	Subject(ssf.Complex(ssf.IssSub(issuer, "alice"), ssf.Opaque("session-1"))).
	Event("CaepSessionRevoked", caep.NewPayload().EventTimestamp(time.Now()).InitiatingEntity("admin").Build()).
	Claims()
signer, err := signing.NewSigner(privateKey, jose.RS256, "key-1") // RSA, ECDSA or Ed25519
set, err := signer.Sign(claims)                                   // typ secevent+jwt, kid key-1
```

## Examples

[`examples/`](examples) holds the ports of the Spring Boot examples: a resource server that rejects
the access tokens of revoked sessions (`go run ./examples/resource-server -demo` runs it against
the in-process test transmitter, `-poll` polls instead), an OIDC client that ends local sessions
when Keycloak reports a revoked session or changed credentials, and a SCIM provisioning
application that mirrors SCIM `Users` from SCIM Events, with a demo service provider of its own.
The two Keycloak applications run against [`examples/keycloak`](examples/keycloak), the Docker
Compose setup with the `ssf-demo` realm shared with the Java and Rust repositories.

## Conformance

The receiver is tested against the OpenID conformance suite's SSF and CAEP receiver test plans,
with push and poll delivery. [`conformance/`](conformance) is a module of its own: the receiver
under test that plays the stream operations a test module expects, the suite started in Docker by
testcontainers-go, and the four plan tests. They are skipped unless asked for, as a plan takes
minutes:

```sh
cd conformance && EASYSSF_CONFORMANCE_TESTS=true go test -run Plan -timeout 60m -v .
```

See [`conformance/README.md`](conformance/README.md) for the plans, the suite image
(`release-v5.3.2`, pinned by digest, the same as in the Java, .NET and Rust repositories) and
manual runs against a suite of your own.

## Not included (yet)

- A transmitter: this is a receiver library. `ssf.NewSET` and `ssf/signing` make and sign SETs
  for tests and small senders; the stream management and delivery of a transmitter are not here.
- An OpenTelemetry or Prometheus implementation of `Metrics`; it is a small interface, implement
  it over your meter.
- Session integrations for gorilla/sessions or scs; `SessionTerminator` and `SubjectMatches` are
  what one needs, see `examples/oidc-client/sessions.go`.

## Build

```sh
go test -race ./...                                   # everything, in-process, no network, no Docker
EASYSSF_DATABASE_TESTS=true EASYSSF_POSTGRES_URL=... EASYSSF_MYSQL_URL=... go test ./receiver/sqlstore
go vet ./... && gofmt -l . && make lint    # golangci-lint and govulncheck
go run ./examples/resource-server -demo
```
