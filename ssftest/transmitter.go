// Package ssftest holds TestTransmitter, a minimal SSF transmitter for tests: it signs SETs,
// serves its metadata and JWK Set, issues access tokens and (SKETCH, to port from the Rust
// easyssf-test crate) emulates the stream management and poll endpoints. It answers
// in-process: its Client is an *http.Client whose transport routes requests for the
// transmitter's host to the handler without a socket, and HTTPHandler mounts the same handler on
// an httptest.Server when a real port is wanted.
package ssftest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/easyssf/easyssf-go/ssf"
	"github.com/easyssf/easyssf-go/ssf/eventtypes"
)

const (
	// Audience is the audience of the SETs the transmitter signs by default.
	Audience = "https://receiver.example"
	// SecEventJWTType is the typ header of a SET (RFC 8417, section 2.3).
	SecEventJWTType = "secevent+jwt"
	// JWTType is the typ header of a plain JWT such as an access token.
	JWTType = "JWT"
	// AccessToken is the access token the token endpoint issues.
	AccessToken = "transmitter-access-token"

	realm         = "/realms/test"
	wellKnownPath = "/.well-known/ssf-configuration"
)

// MetadataLocation is where the transmitter publishes its metadata.
type MetadataLocation int

const (
	// MetadataSSF: SSF 1.0, section 7.2, /.well-known/ssf-configuration followed by the path of
	// the issuer.
	MetadataSSF MetadataLocation = iota
	// MetadataOIDCStyle: /.well-known/ssf-configuration under the path of the issuer, as OpenID
	// Connect Discovery places its document and some transmitters do.
	MetadataOIDCStyle
	// MetadataNone: no metadata is published.
	MetadataNone
)

// SigningKey is an RSA key a transmitter signs with.
type SigningKey struct {
	KeyID string
	Key   *rsa.PrivateKey
}

// GenerateKey makes a fresh key of the given size, for SETs the receiver must reject
// (GenerateKey(1024, "weak")) or ones of another transmitter. SharedKey is faster.
func GenerateKey(bits int, kid string) *SigningKey {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}
	return &SigningKey{KeyID: kid, Key: key}
}

// WithKeyID is the same key under another kid.
func (k *SigningKey) WithKeyID(kid string) *SigningKey { return &SigningKey{KeyID: kid, Key: k.Key} }

// PublicJWK is the public key as a JWK.
func (k *SigningKey) PublicJWK() jose.JSONWebKey {
	return jose.JSONWebKey{Key: &k.Key.PublicKey, KeyID: k.KeyID, Use: "sig"}
}

var (
	sharedOnce sync.Once
	shared     *SigningKey
)

// SharedKey is the 2048 bit key every default transmitter of the process signs with: generating
// one takes a while, and the tests do not depend on the keys of two transmitters differing.
func SharedKey() *SigningKey {
	sharedOnce.Do(func() { shared = GenerateKey(2048, "test-key") })
	return shared
}

// TestTransmitter is a minimal SSF transmitter for tests, see the package documentation. Safe
// for concurrent use.
type TestTransmitter struct {
	issuer    string
	key       *SigningKey
	mu        sync.Mutex
	documents map[string]string
	available atomic.Bool
	requests  atomic.Int64
	userAgent string
	// Client calls the transmitter in-process. Give it to the receiver under test.
	Client *http.Client
}

// New is a transmitter at https://transmitter.example/realms/test with its metadata at the SSF
// location.
func New() *TestTransmitter { return WithMetadata(MetadataSSF, "") }

// WithMetadata is a transmitter that publishes its metadata at the given location, or not at
// all. host is the host of the issuer, transmitter.example if ""; give every transmitter of a
// test its own, as a receiver tells transmitters apart by issuer.
func WithMetadata(location MetadataLocation, host string) *TestTransmitter {
	if host == "" {
		host = "transmitter.example"
	}
	t := &TestTransmitter{issuer: "https://" + host + realm, key: SharedKey(), documents: map[string]string{}}
	t.available.Store(true)
	t.Client = &http.Client{Transport: &inProcess{transmitter: t}}
	t.PublishJWKS(t.key)
	t.PublishMetadata(location)
	return t
}

// Issuer is the issuer, the iss of the SETs.
func (t *TestTransmitter) Issuer() string { return t.issuer }

// Key is the signing key.
func (t *TestTransmitter) Key() *SigningKey { return t.key }

// JWKSURL is where the JWK Set is served.
func (t *TestTransmitter) JWKSURL() string { return t.issuer + "/protocol/openid-connect/certs" }

// Requests is how many requests the transmitter answered.
func (t *TestTransmitter) Requests() int { return int(t.requests.Load()) }

// LastUserAgent is the User-Agent of the last request, "" if none.
func (t *TestTransmitter) LastUserAgent() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.userAgent
}

// SetAvailable simulates an outage: every request fails with 503 while false.
func (t *TestTransmitter) SetAvailable(available bool) { t.available.Store(available) }

// PublishDocument serves json at the given path of the issuer's host.
func (t *TestTransmitter) PublishDocument(path, body string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.documents[path] = body
}

// RemoveDocument stops serving the document at the path.
func (t *TestTransmitter) RemoveDocument(path string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.documents, path)
}

// PublishJWKS serves the public keys as the JWK Set, replacing the one before.
func (t *TestTransmitter) PublishJWKS(keys ...*SigningKey) {
	set := jose.JSONWebKeySet{}
	for _, key := range keys {
		set.Keys = append(set.Keys, key.PublicJWK())
	}
	body, _ := json.Marshal(set)
	t.PublishDocument(realm+"/protocol/openid-connect/certs", string(body))
}

// PublishMetadata serves the transmitter metadata at the given location, removing it from the
// other.
func (t *TestTransmitter) PublishMetadata(location MetadataLocation) {
	t.RemoveDocument(wellKnownPath + realm)
	t.RemoveDocument(realm + wellKnownPath)
	metadata, _ := json.Marshal(map[string]any{
		"issuer":                     t.issuer,
		"jwks_uri":                   t.JWKSURL(),
		"spec_version":               ssf.SpecVersion1_0,
		"delivery_methods_supported": []string{ssf.PushURI, ssf.PollURI},
		"configuration_endpoint":     t.issuer + "/ssf/streams",
		"status_endpoint":            t.issuer + "/ssf/status",
		"add_subject_endpoint":       t.issuer + "/ssf/subjects:add",
		"remove_subject_endpoint":    t.issuer + "/ssf/subjects:remove",
		"verification_endpoint":      t.issuer + "/ssf/verify",
	})
	switch location {
	case MetadataSSF:
		t.PublishDocument(wellKnownPath+realm, string(metadata))
	case MetadataOIDCStyle:
		t.PublishDocument(realm+wellKnownPath, string(metadata))
	}
}

// SetClaims are the claims of a valid SET with a single event whose payload has an
// event_timestamp. eventType is an alias such as CaepSessionRevoked or an event type URI,
// subjectID the sub_id claim, left out if nil.
func (t *TestTransmitter) SetClaims(eventType string, subjectID ssf.Claims) ssf.Claims {
	return t.SetClaimsWithPayload(eventType, subjectID, ssf.Claims{"event_timestamp": time.Now().Unix()})
}

// SetClaimsWithPayload are the claims of a valid SET with a single event and the given payload.
func (t *TestTransmitter) SetClaimsWithPayload(eventType string, subjectID ssf.Claims, payload ssf.Claims) ssf.Claims {
	claims := ssf.Claims{
		"iss":    t.issuer,
		"jti":    newJTI(),
		"iat":    time.Now().Unix(),
		"aud":    Audience,
		"events": ssf.Claims{eventtypes.Resolve(eventType): payload},
	}
	if subjectID != nil {
		claims["sub_id"] = subjectID
	}
	return claims
}

// Set is a valid, signed SET with a single event.
func (t *TestTransmitter) Set(eventType string, subjectID ssf.Claims) string {
	return t.SignSET(t.SetClaims(eventType, subjectID))
}

// SignSET signs the claims as a SET: typed secevent+jwt, with the transmitter's key.
func (t *TestTransmitter) SignSET(claims ssf.Claims) string {
	return Sign(t.key, SecEventJWTType, claims)
}

// AccessTokenFor is an access token of the identity provider, as an OAuth client would present
// it: iss, sub, sid, iat and a five minute exp.
func (t *TestTransmitter) AccessTokenFor(subject, sessionID string, issuedAt time.Time) string {
	return Sign(t.key, JWTType, ssf.Claims{
		"iss": t.issuer, "sub": subject, "sid": sessionID, "iat": issuedAt.Unix(), "exp": time.Now().Unix() + 300,
	})
}

// Sign signs the claims with RS256; typ is the typ header, left out if "".
func Sign(key *SigningKey, typ string, claims ssf.Claims) string {
	return SignWith(key, jose.RS256, typ, claims)
}

// SignWith signs the claims as a JWS in compact serialization with an RSA algorithm of RFC
// 7518: RS256, RS384, RS512, PS256, PS384 or PS512. No minimum key size: tests need to sign with
// keys the receiver has to reject.
func SignWith(key *SigningKey, algorithm jose.SignatureAlgorithm, typ string, claims ssf.Claims) string {
	options := (&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), key.KeyID)
	if typ != "" {
		options = options.WithType(jose.ContentType(typ))
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: algorithm, Key: key.Key}, options)
	if err != nil {
		panic(err)
	}
	payload, _ := json.Marshal(claims)
	jws, err := signer.Sign(payload)
	if err != nil {
		panic(err)
	}
	compact, err := jws.CompactSerialize()
	if err != nil {
		panic(err)
	}
	return compact
}

// Unsigned is the claims as an unsecured JWT (RFC 7519, section 6): alg of none, no signature.
func Unsigned(claims ssf.Claims) string {
	payload, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." + base64.RawURLEncoding.EncodeToString(payload) + "."
}

// ClaimsOf are the claims of a JWS in compact serialization, without any verification. It
// panics if jws is not a JWS whose payload is a JSON object.
func ClaimsOf(jws string) ssf.Claims {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		panic("not a JWS in compact serialization")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		panic(err)
	}
	claims, err := ssf.ParseClaims(payload)
	if err != nil {
		panic(err)
	}
	return claims
}

// ServeHTTP implements http.Handler: the documents, the token endpoint and (SKETCH) the stream
// management and poll endpoints. Mount it on an httptest.Server for a real port.
func (t *TestTransmitter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t.requests.Add(1)
	t.mu.Lock()
	t.userAgent = r.Header.Get("User-Agent")
	document, ok := t.documents[r.URL.Path]
	t.mu.Unlock()
	if !t.available.Load() {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if ok && r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(document))
		return
	}
	// SKETCH: token endpoint, /ssf/streams, /ssf/status, /ssf/poll, /ssf/verify, subjects.
	http.NotFound(w, r)
}

// inProcess is an http.RoundTripper that answers requests for the transmitter's host from its
// handler and refuses every other host, so a test never reaches the network.
type inProcess struct{ transmitter *TestTransmitter }

func (p *inProcess) RoundTrip(r *http.Request) (*http.Response, error) {
	if !strings.HasPrefix(p.transmitter.issuer, r.URL.Scheme+"://"+r.URL.Host) {
		return nil, fmt.Errorf("ssftest: no route to %s://%s, the test transmitter is %s", r.URL.Scheme, r.URL.Host, p.transmitter.issuer)
	}
	recorder := &responseRecorder{header: http.Header{}, status: http.StatusOK}
	p.transmitter.ServeHTTP(recorder, r)
	return &http.Response{
		StatusCode: recorder.status, Status: fmt.Sprintf("%d %s", recorder.status, http.StatusText(recorder.status)),
		Header: recorder.header, Body: &bodyReader{Reader: strings.NewReader(recorder.body.String())},
		Request: r, ContentLength: int64(recorder.body.Len()),
	}, nil
}

type responseRecorder struct {
	header http.Header
	status int
	body   strings.Builder
}

func (r *responseRecorder) Header() http.Header         { return r.header }
func (r *responseRecorder) Write(b []byte) (int, error) { return r.body.Write(b) }
func (r *responseRecorder) WriteHeader(status int)      { r.status = status }

type bodyReader struct{ *strings.Reader }

func (bodyReader) Close() error { return nil }

func newJTI() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%x", b)
}
