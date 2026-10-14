// Package conformance runs the OpenID conformance suite's SSF receiver test plans against a
// receiver under test: the suite started with Testcontainers, the scenarios the receiver plays,
// the plans and the expected outcome of every module, and the receiver under test itself. A port
// of easyssf-test-conformance and easyssf-receiver-spring-boot-conformance-tests of the Java
// library, in a module of its own (github.com/easyssf/easyssf-go/conformance) so that the Docker
// client it needs stays out of the library.
//
// The suite emulates a transmitter and an authorization server; the receiver under test (Run,
// served by Handler) plays the stream operations a test module expects and accepts the events
// it delivers. Every test of the suite emulates a transmitter with new signing keys under the
// same issuer, so every run gets a fresh receiver assembled from the receiver package: token,
// verifier, de-duplication and stream are per run.
//
// The plan tests (plans_test.go) are skipped unless EASYSSF_CONFORMANCE_TESTS=true, as a plan
// takes minutes and needs Docker; cmd/cts runs the receiver under test by hand against a suite,
// and run-plan.sh drives a plan module by module.
package conformance
