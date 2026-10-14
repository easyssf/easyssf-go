package conformance

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/moby/moby/api/types/container"
	mobynet "github.com/moby/moby/api/types/network"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Suite is the OpenID conformance suite the tests run against, started with Testcontainers like
// docker-compose-prebuilt.yml of the suite's repository does: MongoDB, the suite and its nginx
// in front. The suite has to know its public URL before it starts, so nginx is bound to a fixed
// host port and the suite's URL is https://localhost:<port>; the system under test on the Docker
// host is reached from the containers as host.testcontainers.internal. See Settings for the
// images and ports.
type Suite struct {
	settings    Settings
	baseURL     *url.URL
	certificate *x509.Certificate
	client      *APIClient
	network     *tc.DockerNetwork
	containers  []tc.Container
	mu          sync.Mutex
	certFile    string
}

const (
	suitePort            = "8080/tcp"
	nginxPort            = "8443/tcp"
	nginxCertificatePath = "/etc/ssl/certs/nginx-selfsigned.crt"
)

// StartSuite starts the suite and waits until its API is available. Stop it with Close; the
// containers are removed by the Testcontainers reaper otherwise.
func StartSuite(ctx context.Context, settings Settings, log *slog.Logger) (*Suite, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	baseURL, _ := url.Parse("https://localhost:" + strconv.Itoa(settings.SuitePort))
	log.Info("Starting conformance suite", "image", settings.SuiteImage, "url", baseURL)
	nw, err := network.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not create the network of the conformance suite: %w", err)
	}
	suite := &Suite{settings: settings, baseURL: baseURL, network: nw}
	fail := func(err error) (*Suite, error) {
		suite.Close()
		return nil, err
	}
	mongodb, err := tc.Run(ctx, settings.SuiteMongoDBImage,
		network.WithNetwork([]string{"mongodb"}, nw),
		tc.WithExposedPorts("27017/tcp"),
		tc.WithLogConsumers(&logConsumer{log: log.With("container", "mongodb")}),
		tc.WithWaitStrategy(wait.ForListeningPort("27017/tcp").WithStartupTimeout(2*time.Minute)))
	if mongodb != nil {
		suite.containers = append(suite.containers, mongodb)
	}
	if err != nil {
		return fail(fmt.Errorf("could not start MongoDB for the conformance suite: %w", err))
	}
	server, err := tc.Run(ctx, settings.SuiteImage,
		network.WithNetwork([]string{"server"}, nw),
		tc.WithExposedPorts(suitePort),
		tc.WithEnv(map[string]string{
			"BASE_URL":      baseURL.String(),
			"BASE_MTLS_URL": baseURL.String(),
			"MONGODB_HOST":  "mongodb",
			// The suite pins MongoDB's feature compatibility version to the one it runs in
			// production (6.0) and refuses to start otherwise. The tests run a current MongoDB,
			// so the suite is told not to touch the version (an empty target skips the step).
			"OPENID_MONGODB_TARGETFEATURECOMPATIBILITYVERSION": "",
			// the dev profile needs no login
			"SPRING_PROFILES_ACTIVE": "dev",
			"OIDC_GOOGLE_CLIENTID":   "google-client",
			"OIDC_GOOGLE_SECRET":     "google-secret",
			"OIDC_GITLAB_CLIENTID":   "gitlab-client",
			"OIDC_GITLAB_SECRET":     "gitlab-secret",
		}),
		// the suite reaches the system under test on the Docker host as host.testcontainers.internal
		tc.WithHostPortAccess(settings.ReceiverPort),
		tc.WithLogConsumers(&logConsumer{log: log.With("container", "suite")}),
		tc.WithWaitStrategy(wait.ForListeningPort(suitePort).WithStartupTimeout(4*time.Minute)))
	if server != nil {
		suite.containers = append(suite.containers, server)
	}
	if err != nil {
		return fail(fmt.Errorf("could not start the conformance suite: %w", err))
	}
	nginx, err := tc.Run(ctx, settings.SuiteNginxImage,
		network.WithNetwork([]string{"nginx"}, nw),
		tc.WithExposedPorts(nginxPort),
		tc.WithHostConfigModifier(func(hostConfig *container.HostConfig) {
			hostConfig.PortBindings = mobynet.PortMap{mobynet.MustParsePort(nginxPort): []mobynet.PortBinding{{HostIP: netip.IPv4Unspecified(), HostPort: strconv.Itoa(settings.SuitePort)}}}
		}),
		tc.WithLogConsumers(&logConsumer{log: log.With("container", "nginx"), level: slog.LevelDebug}),
		tc.WithWaitStrategy(wait.ForListeningPort(nginxPort).WithStartupTimeout(2*time.Minute)))
	if nginx != nil {
		suite.containers = append(suite.containers, nginx)
	}
	if err != nil {
		return fail(fmt.Errorf("could not start the nginx of the conformance suite: %w", err))
	}
	certificate, err := nginxCertificate(ctx, nginx)
	if err != nil {
		return fail(err)
	}
	suite.certificate = certificate
	// the self-signed certificate of nginx names its host in the Common Name only, which Go
	// does not match, so the certificate itself is pinned instead of verified by host name
	suite.client = NewAPIClient(baseURL, NewHTTPClient(certificate, false, false))
	if err := suite.client.WaitUntilAvailable(ctx, 4*time.Minute); err != nil {
		return fail(err)
	}
	log.Info("Conformance suite is available", "image", settings.SuiteImage, "url", baseURL)
	return suite, nil
}

// BaseURL is the URL under which the tests reach the suite, also the base of the issuers of its
// test instances (<base>/test/a/<alias>).
func (s *Suite) BaseURL() *url.URL { return s.baseURL }

// Settings are the settings the suite was started with.
func (s *Suite) Settings() Settings { return s.settings }

// SystemUnderTestHost is the host under which the suite reaches the system under test.
func (s *Suite) SystemUnderTestHost() string { return tc.HostInternal }

// ReceiverPushURL is the URL under which the suite reaches the push endpoint of the receiver
// under test: Settings.ReceiverPushURL, or https://<system under test host>:<receiver port>/ssf/push.
func (s *Suite) ReceiverPushURL() string {
	if s.settings.ReceiverPushURL != "" {
		return s.settings.ReceiverPushURL
	}
	return fmt.Sprintf("https://%s:%d/ssf/push", s.SystemUnderTestHost(), s.settings.ReceiverPort)
}

// Client is the API of the suite.
func (s *Suite) Client() *APIClient { return s.client }

// HTTPClient is an HTTP client for the receiver under test that trusts the suite's TLS
// certificate, for calling the transmitter the suite emulates.
func (s *Suite) HTTPClient() *http.Client { return NewHTTPClient(s.certificate, false, false) }

// Certificate is the TLS certificate of the suite.
func (s *Suite) Certificate() *x509.Certificate { return s.certificate }

// CertificateFile is the TLS certificate of the suite as a PEM file, for the trust store of a
// system under test that reads one.
func (s *Suite) CertificateFile() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.certFile != "" {
		return s.certFile, nil
	}
	file, err := os.CreateTemp("", "conformance-suite-*.pem")
	if err != nil {
		return "", err
	}
	defer file.Close()
	if err := pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: s.certificate.Raw}); err != nil {
		return "", err
	}
	s.certFile = file.Name()
	return s.certFile, nil
}

// Close stops the containers and removes the network.
func (s *Suite) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for i := len(s.containers) - 1; i >= 0; i-- {
		_ = s.containers[i].Terminate(ctx)
	}
	if s.network != nil {
		_ = s.network.Remove(ctx)
	}
	s.mu.Lock()
	if s.certFile != "" {
		_ = os.Remove(s.certFile)
		s.certFile = ""
	}
	s.mu.Unlock()
}

func nginxCertificate(ctx context.Context, nginx tc.Container) (*x509.Certificate, error) {
	reader, err := nginx.CopyFileFromContainer(ctx, nginxCertificatePath)
	if err != nil {
		return nil, fmt.Errorf("could not read the TLS certificate of the conformance suite from %s: %w", nginxCertificatePath, err)
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("the TLS certificate of the conformance suite at %s is not PEM", nginxCertificatePath)
	}
	return x509.ParseCertificate(block.Bytes)
}

// logConsumer forwards the log of a container to slog.
type logConsumer struct {
	log   *slog.Logger
	level slog.Level
}

func (c *logConsumer) Accept(entry tc.Log) {
	c.log.Log(context.Background(), c.level, string(entry.Content))
}

var (
	sharedMu    sync.Mutex
	sharedSuite *Suite
)

// SharedSuite is the one suite the plan tests of a process share, started on first use with
// SettingsFromEnvironment. CloseSharedSuite stops it.
func SharedSuite(ctx context.Context, log *slog.Logger) (*Suite, error) {
	sharedMu.Lock()
	defer sharedMu.Unlock()
	if sharedSuite != nil {
		return sharedSuite, nil
	}
	suite, err := StartSuite(ctx, SettingsFromEnvironment(), log)
	if err != nil {
		return nil, err
	}
	sharedSuite = suite
	return suite, nil
}

// CloseSharedSuite stops the shared suite, if one was started.
func CloseSharedSuite() {
	sharedMu.Lock()
	defer sharedMu.Unlock()
	if sharedSuite != nil {
		sharedSuite.Close()
		sharedSuite = nil
	}
}
