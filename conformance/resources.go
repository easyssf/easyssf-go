package conformance

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"errors"
	"net/http"
)

// The TLS material of the receiver under test and the test CA, on the file system of this
// module and embedded here: the suite only accepts https push endpoints and does not check the
// certificate, so a self-signed one for localhost, host.testcontainers.internal and
// host.docker.internal does.

//go:embed tls/receiver.pem
var receiverCertificatePEM []byte

//go:embed tls/receiver-key.pem
var receiverKeyPEM []byte

//go:embed test-ca.pem
var testCAPEM []byte

// ReceiverCertificatePEM is the TLS certificate of the receiver under test, tls/receiver.pem.
func ReceiverCertificatePEM() []byte { return receiverCertificatePEM }

// ReceiverKeyPEM is the private key of the receiver under test, tls/receiver-key.pem.
func ReceiverKeyPEM() []byte { return receiverKeyPEM }

// TestCAPEM is the CA that issued the receiver's certificate, test-ca.pem.
func TestCAPEM() []byte { return testCAPEM }

// ReceiverTLSConfig is the server TLS configuration of the receiver under test.
func ReceiverTLSConfig() (*tls.Config, error) {
	certificate, err := tls.X509KeyPair(receiverCertificatePEM, receiverKeyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}, nil
}

// NewHTTPClient is the HTTP client the receiver calls the suite (and the suite's API) with:
// trusting the given certificate, for any host name if verifyHostname is false (the self-signed
// certificate of a locally running suite is issued for localhost, not localhost.emobix.co.uk),
// or any certificate at all if trustAll is set, only for a suite running locally. A nil
// certificate without trustAll uses the system roots. Calls carry the User-Agent
// easyssf-receiver-conformance.
func NewHTTPClient(trusted *x509.Certificate, trustAll, verifyHostname bool) *http.Client {
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	switch {
	case trustAll:
		config.InsecureSkipVerify = true //nolint:gosec // a local suite with a self-signed certificate, by configuration
	case trusted != nil && !verifyHostname:
		config.InsecureSkipVerify = true //nolint:gosec // the certificate itself is checked below, only its host name is not
		// VerifyConnection, not VerifyPeerCertificate: it runs for resumed sessions as well
		config.VerifyConnection = func(state tls.ConnectionState) error {
			for _, certificate := range state.PeerCertificates {
				if certificate.Equal(trusted) {
					return nil
				}
			}
			return errors.New("the certificate of the conformance suite is not the trusted one")
		}
	case trusted != nil:
		pool := x509.NewCertPool()
		pool.AddCert(trusted)
		config.RootCAs = pool
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = config
	return &http.Client{Transport: &userAgentTransport{next: transport}}
}

type userAgentTransport struct{ next http.RoundTripper }

func (t *userAgentTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Header.Get("User-Agent") == "" {
		r = r.Clone(r.Context())
		r.Header.Set("User-Agent", "easyssf-receiver-conformance")
	}
	return t.next.RoundTrip(r)
}
