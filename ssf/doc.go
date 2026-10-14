// Package ssf holds the vocabulary of the OpenID Shared Signals Framework (SSF 1.0), shared by
// receivers and (later) transmitters: Security Event Tokens, subjects, delivery methods, stream
// configuration and transmitter metadata. The typed CAEP, RISC and SCIM events live in the
// sub-packages caep, risc and scim, the event type URIs and their aliases in eventtypes.
//
// Raw claims stay map[string]any as decoded by encoding/json, typed accessors sit on top, as
// JsonElement does in the .NET port and serde_json::Value in the Rust port. Values are immutable
// once built; a receiver passes them around by pointer.
//
// A port of easyssf-core of the Java library; the Java code and the specifications are the
// reference for protocol behaviour.
package ssf
