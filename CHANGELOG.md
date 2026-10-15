# Changelog

All notable changes to this project will be documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the version follows the Java library.

## [Unreleased]

### Added

- `ssf`: the vocabulary of SSF 1.0 ported from `easyssf-core` of the Java library: `EventToken`,
  `Subject` and `SubjectIdentifier` with the subject builders (`IssSub`, `Email`, `Opaque`,
  `Complex`, ...), `DeliveryMethod`, `StreamConfiguration`, `StreamStatus`,
  `TransmitterMetadata`; `ssf/eventtypes` with the event type URIs and the alias registry.
- `ssf/caep`, `ssf/risc`, `ssf/scim`: the typed events of CAEP 1.0, RISC 1.0 and SCIM Events
  (RFC 9967) with their kinds and operations, the common and event-specific claims
  (`credential_type`, `current_level`, `reason`, `new-value`, `data`, `attributes`, ...) and the
  `scim` subject (`uri`, `id`, `externalId`, resource type).
- `receiver`: `JWTVerifier` on go-jose with the JWK Set cache `HTTPJWKSetSource` and its
  rate-limited refresh, `IssuerRoutingVerifier`, `MetadataResolver` with `URIPolicy` and the two
  well-known locations, `JTIDedupStore` with the lease and claim renewal and
  `InMemoryJTIDedupStore`, `Processor` with critical subject members, claim renewal and panic
  recovery, `PushHandler` as `http.Handler` and by issuer, `Context`, `Handler`, `HandlerFunc`,
  `ForEvent`, `TokenRevocationStore` with `InMemoryTokenRevocationStore`,
  `TokenRevocationHandler` and `RevocationMiddleware`, `Metrics` with `NoopMetrics`.
- `receiver`: stream management (SSF 1.0, section 8.1): `StreamClient` for the configuration,
  status, subject and verification endpoints with a token refresh on 401, `ReceiverStream`,
  `StreamRegistrar` that reuses, updates or creates the stream in the background with retries
  and deletes it on shutdown when asked, `StreamVerification` with `InvalidState`; `StreamError`
  and `IssuerMismatchError`.
- `receiver`: poll delivery (RFC 8936): `Poller` with short and long polling, acknowledgements
  and error reports riding on the next request, `Retry-After` and the rate limit fallback, a
  flush on stop and a wake-up when the stream is registered; `PendingAck`, `PollAckStore` and
  `InMemoryPollAckStore`; `TokenProvider` with `NoToken`, `FixedToken` and
  `ClientCredentialsTokenProvider` (client credentials grant, basic or post authentication, a
  cache with a safety window) and `TokenInvalidator`.
- `receiver`: session termination: `SessionTerminator` over the subject of the event,
  `SessionTerminationHandler`, and `SubjectMatches` / `SubjectMatchesWith` that match the subject
  of an event with the claims of a logged-in user, including `scim` subjects by configurable
  attribute-claim pairs; `WithSessionTerminator` and `easyssf.receiver.session-termination`.
- `receiver`: the typed handlers `CaepHandler`, `RiscHandler` and `ScimHandler` with the
  embeddable `Noop...` implementations, the `Caep`, `Risc` and `Scim` adapters and the
  `Dispatch...Event` functions.
- `receiver`: `Config`, the options of the Spring Boot starter and the .NET port in kebab-case
  with `json`, `yaml` and `mapstructure` tags, `DefaultConfig` and `Validate` reporting every
  failure at once, including `data` and `session-termination`; `Receiver`, which assembles the
  transmitters with their verifier, token provider, stream client, registrar and poller, the
  processor, the push handler and the stores from it, with functional options; `Transmitter`
  with `Start`/`Stop`; `Health` with the status and detail of every transmitter; `Metrics`
  gained `PollCompleted` and `PendingAcksChanged`.
- `receiver/sqlstore`: the three stores on `database/sql` in the tables shared with Java, .NET
  and Rust (`JTIDedupStore`, `TokenRevocationStore`, `PollAckStore`), `Operations` with the
  `SQLite`, `PostgreSQL` and `MySQL` dialects (placeholders rewritten for PostgreSQL), the
  schema check and creation with the upgrades of older releases, `Cleanup`, and `Stores` built
  from `easyssf.receiver.data`; `schema.sql` and `migration/*.sql` are the files of the Java
  library byte for byte.
- `receiver`: `URIPolicy.CheckRedirect`: a redirect of any call to the transmitter is followed
  only within the origin of the request (`SameOrigin`: scheme, host and effective port) and
  only where the policy allows the scheme, whatever the
  `http.Client`'s own `CheckRedirect`; an https endpoint cannot send the receiver and its
  credentials to http or elsewhere. The poll endpoint of a registered stream, `oauth2.token-uri`
  and `poll.endpoint-url` are checked against the policy like the other endpoints.
- `ssf/eventtypes`: `CheckAlias`, the check of `RegisterAlias` without the registration.
  `Config.Validate` uses it and changes nothing any more; `receiver.New` registers the aliases
  once the whole configuration passed.
- `receiver`: `Poller`, `StreamRegistrar` and `Receiver` clear their running state when the
  context of `Start` is cancelled, so that `IsRunning` is accurate and `Start` works again;
  `Stop` still sends the acknowledgements owed and deletes the streams configured for it.
- `receiver`: `Authorizer`, what every call to the transmitter goes through: `BearerToken` over
  a `TokenProvider`, `StaticHeaders`, `EndpointHeaders` by `Endpoint` (`EndpointOf(ctx)`),
  `AuthorizerFunc` and `Authorizers` to chain them; `NewStreamClient` and `NewPoller` take one
  (every `TokenProvider` of the library is one); `MetadataResolver` and `HTTPJWKSetSource`
  accept one too; `easyssf.receiver.headers` sends fixed headers with every call.
- `receiver`: `RetryOptions` and `easyssf.receiver.http.retry`: management, metadata and JWK
  Set calls that fail with a connection error or 408, 429, 500, 502, 503 or 504 are tried
  again with exponential backoff, honouring `Retry-After`; two retries by default.
- `ssf`: `NewSET`, a builder for the claims of a SET (`JTI`, `IssuedAt`, `Audience`, `Subject`,
  `Txn`, `Event` resolving aliases, `Claim`), `NewJTI`; `ssf/signing` with `Signer` over RSA,
  ECDSA and Ed25519 keys, `Sign` (typ `secevent+jwt`), `SignTyped`, `PublicJWK` and `JWKSet`;
  `caep.NewPayload` for the common claims of a CAEP event; `TestTransmitter.Signer`.
- `ssftest`: `TestTransmitter` with the signing key, the JWK Set, the metadata at both
  locations, the token endpoint, the stream management, status, subject and verification
  endpoints and the poll endpoint with long polling, `QueueSet`, `AcknowledgedSets`,
  `ReportedErrors`, `Streams`, `ExpireAccessTokens`, `SetAvailable`, `ClientFor` for several
  transmitters, `Eventually` and `During`.
- `examples/resource-server`, `examples/oidc-client` and `examples/scim-provisioning`: the ports
  of the Spring Boot examples, and `examples/keycloak`, the Docker Compose setup with the
  `ssf-demo` realm of the Java repository.
- `conformance`, a module of its own: the OpenID conformance suite started with testcontainers-go
  (`Suite`, `APIClient`), the receiver under test that plays the scenarios (`Run`, `Runner`,
  `Handler`, `cmd/cts`), the plans with the expected outcome of every module (`RunPlan`), the
  suite configurations, TLS material and `run-plan.sh` of the Java harness, and the nightly
  `Conformance` workflow.
- Tests ported from the Java and Rust suites: the verifier, the dedup store, the processor, the
  push handler, stream management and verification, the poller and its rate limiting, the
  transmitters, the configured receiver, session termination and the subject matcher, the typed
  handlers, the stores on SQLite (PostgreSQL and MySQL with `EASYSSF_DATABASE_TESTS=true`) and
  two receiver instances on one database.
