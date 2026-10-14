# Changelog

All notable changes to this project will be documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the version follows the Java library.

## [Unreleased]

### Added

- `ssf`: the vocabulary of SSF 1.0 ported from `easyssf-core` of the Java library: `EventToken`,
  `Subject` and `SubjectIdentifier` with the subject builders (`IssSub`, `Email`, `Opaque`,
  `Complex`, ...), `DeliveryMethod`, `StreamConfiguration`, `StreamStatus`,
  `TransmitterMetadata`; `ssf/eventtypes` with the event type URIs and the alias registry;
  `ssf/caep` with the event kinds and the common claims (the per-kind accessors, `ssf/risc` and
  `ssf/scim` are stubs).
- `receiver`: `JWTVerifier` on go-jose with the JWK Set cache `HTTPJWKSetSource` and its
  rate-limited refresh, `IssuerRoutingVerifier`, `MetadataResolver` with `URIPolicy` and the two
  well-known locations, `JTIDedupStore` with the lease and claim renewal and
  `InMemoryJTIDedupStore`, `Processor` with critical subject members, claim renewal and panic
  recovery, `PushHandler` as `http.Handler` and by issuer, `Context`, `Handler`, `HandlerFunc`,
  `ForEvent`, `TokenRevocationStore` with `InMemoryTokenRevocationStore`,
  `TokenRevocationHandler` and `RevocationMiddleware`, `SessionTerminator` and
  `SessionTerminationHandler`, `Metrics` with `NoopMetrics`.
- `receiver`: `Config`, the options of the Spring Boot starter and the .NET port in kebab-case
  with `json`, `yaml` and `mapstructure` tags, `DefaultConfig` and `Validate` reporting every
  failure at once; `Receiver`, which assembles the transmitters, the verifier, the processor, the
  push handler and the stores from it, with functional options.
- `receiver`: the shapes of `StreamClient`, `StreamRegistrar`, `StreamVerification`,
  `TokenProvider`, `Poller`, `PollAckStore` and `InMemoryPollAckStore`; their protocol bodies
  are marked `SKETCH`.
- `ssftest`: `TestTransmitter` with the signing key, the JWK Set, the metadata at both
  locations, `Set`, `SignSET`, `Sign`, `SignWith`, `Unsigned` and `ClaimsOf`, answering
  in-process through the `*http.Client` it hands out.
- `examples/resource-server`: the resource server with a `-demo` mode against the test
  transmitter.
- Tests ported from `NimbusSsfSetVerifierTests`, `InMemorySsfJtiDedupStoreTests`,
  `SsfPushHandlerTests` and the first of `SsfSetProcessorTests` and
  `SsfTokenRevocationEventHandlerTests`, plus the `ssf` unit tests.
