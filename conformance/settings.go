package conformance

import (
	"os"
	"strconv"
	"strings"
)

// The suite images and ports, taken from environment variables (CTS_SUITE_IMAGE, ...). The
// images are the suite release easyssf is tested with, release-v5.3.2 of 2026-10-09, the first
// release with the SSF receiver tests as they are on master (the poll race of release-v5.3.1
// included), pinned by the digest of its multi-platform image: the single place to change them.
const (
	// DefaultSuiteImage is the conformance suite image.
	DefaultSuiteImage = "registry.gitlab.com/openid/conformance-suite@sha256:c795df1b151e0c2f2e40f17a2470991cc38bc91628449e9bb090e2372fe8b822"
	// DefaultSuiteNginxImage is its nginx image.
	DefaultSuiteNginxImage = "registry.gitlab.com/openid/conformance-suite/nginx@sha256:607458218abb58204201e4d283af90177d6b542535a99a21041d399a1505a6a0"
	// DefaultSuiteMongoDBImage is its MongoDB image. The suite's own compose file runs MongoDB
	// 6.0.13, as the suite does in production; for the tests a current release, with far fewer
	// known vulnerabilities, works just as well: mongo:9.0.2-noble, pinned by digest.
	DefaultSuiteMongoDBImage = "mongo@sha256:61dd87ff554dc20386c63ebe1f7ede27314370ad5a7bf357c685fab424672158"
	// DefaultSuitePort is the host port the suite listens on. Fixed, as the suite has to know
	// its own URL before it starts.
	DefaultSuitePort = 18443
	// DefaultReceiverPort is the port the receiver under test listens on. Fixed, as the suite
	// reaches it by its push URL.
	DefaultReceiverPort = 9444
)

// Settings say how the conformance tests start the suite and expose the system under test.
type Settings struct {
	SuiteImage        string
	SuiteNginxImage   string
	SuiteMongoDBImage string
	SuitePort         int
	ReceiverPort      int
	// ReceiverPushURL is the push URL the suite is to deliver to, when the default of
	// https://<host as seen from the suite>:<receiver port>/ssf/push does not fit.
	ReceiverPushURL string
}

// SettingsFromEnvironment are the settings from CTS_SUITE_IMAGE, CTS_SUITE_NGINX_IMAGE,
// CTS_SUITE_MONGODB_IMAGE, CTS_SUITE_PORT, CTS_RECEIVER_PORT and CTS_RECEIVER_PUSH_URL, with the
// defaults for what is not set.
func SettingsFromEnvironment() Settings {
	return Settings{
		SuiteImage:        env("CTS_SUITE_IMAGE", DefaultSuiteImage),
		SuiteNginxImage:   env("CTS_SUITE_NGINX_IMAGE", DefaultSuiteNginxImage),
		SuiteMongoDBImage: env("CTS_SUITE_MONGODB_IMAGE", DefaultSuiteMongoDBImage),
		SuitePort:         envInt("CTS_SUITE_PORT", DefaultSuitePort),
		ReceiverPort:      envInt("CTS_RECEIVER_PORT", DefaultReceiverPort),
		ReceiverPushURL:   env("CTS_RECEIVER_PUSH_URL", ""),
	}
}

func env(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func envInt(name string, fallback int) int {
	if value, err := strconv.Atoi(env(name, "")); err == nil && value > 0 {
		return value
	}
	return fallback
}
