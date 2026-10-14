# easyssf-go

Building blocks for the
[OpenID Shared Signals Framework (SSF)](https://openid.net/specs/openid-sharedsignals-framework-1_0.html)
in Go, for applications that receive security events: a **receiver** library on `net/http` that
mounts on any Go web framework, an in-process **test transmitter**, and (to come) database stores
on `database/sql`. A port of [easyssf for Java](https://github.com/easyssf/easyssf), following the
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
rcv.Start(ctx)                                        // registers the stream, starts polling
mux.Handle("POST "+rcv.PushEndpointPath(), rcv.PushHandler()) // POST /ssf/push
```

| | |
|---|---|
| **Status** | **Sketch**, pre-1.0; the version will follow the Java library (`0.7.0-alpha.N`). See [What is left](#what-is-left). |
| **Go** | 1.24 or later, no cgo |
| **Dependencies** | `github.com/go-jose/go-jose/v4` for JWS and JWK; everything else is the standard library |
| **License** | Apache-2.0 |

## Packages

| Package | Holds |
|---|---|
| `ssf` | The vocabulary: SETs, subjects, delivery methods, stream configuration, transmitter metadata; `ssf/eventtypes` the event type URIs with aliases; `ssf/caep`, `ssf/risc`, `ssf/scim` the typed events |
| `receiver` | The receiver: verification, de-duplication with a lease, push and poll, stream management, typed handlers, token revocation, session termination, metrics; `Config` and `Receiver`, which assembles a receiver from it; `PushHandler` (an `http.Handler`) and `RevocationMiddleware` |
| `ssftest` | `TestTransmitter`: signs SETs, serves metadata and the JWK Set, in-process through an `*http.Client` it hands out, no socket involved |
| `receiver/sqlstore` | *(to come)* The three tables shared with Java, .NET and Rust, on `database/sql` |

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
  (`CaepSessionRevoked`), and lets you register aliases for vendor specific types.
- **Receives pushed SETs** (RFC 8935): checks the transmitter's `Authorization` header in constant
  time, verifies, **skips SETs it has already processed** (`jti` de-duplication with a lease and
  claim renewal, so a SET another instance is handling is left alone and one abandoned by a crash
  is taken over), hands verified events to the handlers, answers `202`, `400` with an error
  document, `401`, `413`, `500` or `503`. The handlers run detached from the request context and a
  panic in one is a failed handler, so a transmitter that disconnects does not cancel them.
- **Discovers the transmitter** from its `.well-known/ssf-configuration`, at the SSF location and
  at the one OpenID providers tend to use, and holds its issuer and endpoints to `https` unless a
  loopback address or `allow-insecure-http` says otherwise.
- **Revokes access tokens**: `session-revoked` events fill a `TokenRevocationStore`;
  `RevocationMiddleware` rejects tokens with that `sid` or that `sub` issued up to the event. A
  `SessionTerminator` ends server-side sessions as the event arrives.
- Records **metrics** through the `Metrics` interface under the Java names and reports its
  **health**.
- *Sketched, not finished:* **stream management** (`StreamClient`, `StreamRegistrar`) and
  **polling** (RFC 8936, `Poller`, `PollAckStore`), the typed CAEP/RISC/SCIM handlers, the
  database stores. The types and their documentation are in place; see [What is left](#what-is-left).

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

The audience of the stream is learned from the registration, so `expected-audience` is not needed.
Several transmitters go under `easyssf.receiver.transmitters.<name>`, each with the same settings;
the one at `easyssf.receiver` is named `default`. `receiver.WithTransmitterCustomizer` replaces
parts of any transmitter before it is built.

Every setting, with its default, is documented on `receiver.Config` and its sub-structs
(`go doc ./receiver Config`); the keys are those of the
[.NET configuration table](https://github.com/easyssf/easyssf-dotnet#configuration) in
kebab-case, with durations as strings such as `"30s"` or `"24h"`.

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
the processor; see `receiver/processor_test.go`.

### Sharing state between instances

A SET is pushed to one instance of an application. The in-memory stores are lost on restart and
not shared; `receiver/sqlstore` *(to come)* keeps the processed SETs, the revocations and the
acknowledgements a poller owes in the database of the application, in the tables of the Java
library (`EASYSSF_PROCESSED_SET`, `EASYSSF_REVOCATION`, `EASYSSF_POLL_ACK`). Until then, or on
another store, implement `JTIDedupStore`, `TokenRevocationStore` and `PollAckStore` and give them
to `receiver.New` with `WithDedupStore`, `WithTokenRevocationStore` and `WithPollAckStore`.

## Testing your receiver

`ssftest.TestTransmitter` signs SETs, serves its metadata and JWK Set and (to come) hands out
access tokens and emulates the stream management and poll endpoints, all in-process through the
`*http.Client` it hands out: give it to the receiver as its HTTP client, no socket is involved.

```go
transmitter := ssftest.New()
rcv, err := receiver.New(configFor(transmitter.Issuer()), receiver.WithHTTPClient(transmitter.Client))
set := transmitter.Set("CaepSessionRevoked", ssf.Complex(ssf.IssSub(transmitter.Issuer(), "alice"), ssf.Opaque("session-1")))
// POST set to /ssf/push, or transmitter.QueueSet(set) for a polling receiver (to come)
```

`transmitter.SetAvailable(false)` simulates an outage, `ssftest.GenerateKey(1024, "weak")` makes
keys a receiver has to reject, `ssftest.Sign` and `ssftest.SignWith` sign claims with any key and
algorithm, `ssftest.Unsigned` makes an `alg: none` token.

## Examples

[`examples/resource-server`](examples/resource-server) is the port of the Spring Boot resource
server: it receives events over push, logs them and rejects access tokens of revoked sessions.
`go run ./examples/resource-server -demo` runs it against the in-process test transmitter and
pushes one SET to itself; with `SSF_TRANSMITTER_ISSUER` and friends it runs against the Keycloak
compose setup of the Java repository.

## What is left

This repository is a sketch to extend. The vertical slice push → verify → dedup → handlers →
revocation is complete and tested against the Java test suite; what remains is listed in
[`AGENTS.md`](AGENTS.md#what-the-sketch-has-and-what-is-left), each item marked `SKETCH` in the
code with the Rust file to port it from.

## Build

```sh
go test -race ./...                      # everything, in-process, no network, no Docker
go vet ./... && gofmt -l . && staticcheck ./...
go run ./examples/resource-server -demo
```
