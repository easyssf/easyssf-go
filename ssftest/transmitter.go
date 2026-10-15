// Package ssftest holds TestTransmitter, a minimal SSF transmitter / identity provider for the
// tests of a receiver: it publishes transmitter metadata and a JWK Set, signs SETs and access
// tokens, issues access tokens for the client credentials grant and offers stream management and
// a poll endpoint that behave like the ones of Keycloak. It answers in-process: its Client is an
// *http.Client whose transport routes requests for the transmitter's host to the handler without
// a socket, and ServeHTTP mounts the same handler on an httptest.Server when a real port is
// wanted. A port of the easyssf-test crate of the Rust port.
//
//	transmitter := ssftest.New()
//	claims := transmitter.SetClaims("CaepSessionRevoked", ssf.Complex(ssf.IssSub(transmitter.Issuer(), "alice"), ssf.Opaque("session-1")))
//	claims["aud"] = "https://my-app.example"
//	encodedSET := transmitter.SignSET(claims)
//	// POST encodedSET to /ssf/push, or transmitter.QueueSet(encodedSET) for a polling receiver
package ssftest

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/easyssf/easyssf-go/ssf"
	"github.com/easyssf/easyssf-go/ssf/eventtypes"
	"github.com/easyssf/easyssf-go/ssf/signing"
)

const (
	// Audience is the audience of the SETs the transmitter signs by default.
	Audience = "https://receiver.example"
	// ClientID is the client id the token endpoint accepts.
	ClientID = "receiver"
	// ClientSecret is the client secret the token endpoint accepts.
	ClientSecret = "receiver-secret"
	// AccessToken is the access token the token endpoint issues until ExpireAccessTokens.
	AccessToken = "transmitter-access-token"
	// SecEventJWTType is the typ header of a SET (RFC 8417, section 2.3).
	SecEventJWTType = signing.SecEventJWTType
	// JWTType is the typ header of a plain JWT such as an access token.
	JWTType = signing.JWTType

	realm         = "/realms/test"
	wellKnownPath = "/.well-known/ssf-configuration"
	jwksPath      = "/protocol/openid-connect/certs"
	tokenPath     = "/protocol/openid-connect/token"
	pollPath      = "/ssf/poll"
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

// ReportedError is an error a polling receiver reported for a SET (the setErrs member of a poll
// request, RFC 8936, section 2.2).
type ReportedError struct {
	JTI         string
	Code        string
	Description string
}

type queuedSET struct{ jti, set string }

// TestTransmitter is a minimal SSF transmitter for tests, see the package documentation. Safe
// for concurrent use.
type TestTransmitter struct {
	issuer string
	key    *SigningKey
	// Client calls the transmitter in-process. Give it to the receiver under test.
	Client *http.Client

	available atomic.Bool
	requests  atomic.Int64
	tokens    atomic.Int64
	polls     atomic.Int64

	mu                   sync.Mutex
	documents            map[string]string
	streams              []ssf.Claims
	queued               []queuedSET
	acknowledged         []string
	reportedErrors       []ReportedError
	verificationRequests []string
	addedSubjects        []ssf.Claims
	removedSubjects      []ssf.Claims
	lastPollRequest      ssf.Claims
	longPollHold         time.Duration
	validAccessToken     string
	streamIssuer         string
	userAgent            string
	queuedChanged        chan struct{} // closed and replaced whenever a SET is queued
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
	t := &TestTransmitter{issuer: "https://" + host + realm, key: SharedKey(), documents: map[string]string{},
		validAccessToken: AccessToken, queuedChanged: make(chan struct{})}
	t.available.Store(true)
	t.Client = ClientFor(t)
	t.PublishJWKS(t.key)
	t.PublishMetadata(location)
	return t
}

// Issuer is the issuer of the transmitter: the iss of every SET and the base of its endpoints.
func (t *TestTransmitter) Issuer() string { return t.issuer }

// Key is the key the transmitter signs with.
func (t *TestTransmitter) Key() *SigningKey { return t.key }

// JWKSURL is where the JWK Set is published.
func (t *TestTransmitter) JWKSURL() string { return t.issuer + jwksPath }

// TokenURL is the token endpoint.
func (t *TestTransmitter) TokenURL() string { return t.issuer + tokenPath }

// PollURL is the poll endpoint.
func (t *TestTransmitter) PollURL() string { return t.issuer + pollPath }

// Host is the host of the issuer.
func (t *TestTransmitter) Host() string {
	u, _ := url.Parse(t.issuer)
	return u.Host
}

// Requests is how many HTTP requests the transmitter received so far.
func (t *TestTransmitter) Requests() int { return int(t.requests.Load()) }

// TokenRequests is how many token requests were answered with a token.
func (t *TestTransmitter) TokenRequests() int { return int(t.tokens.Load()) }

// PollRequests is how many poll requests were received.
func (t *TestTransmitter) PollRequests() int { return int(t.polls.Load()) }

// LastPollRequest is the body of the last poll request, empty if none was received.
func (t *TestTransmitter) LastPollRequest() ssf.Claims {
	t.mu.Lock()
	defer t.mu.Unlock()
	return copyClaims(t.lastPollRequest)
}

// LastUserAgent is the User-Agent of the most recent request, "" if none.
func (t *TestTransmitter) LastUserAgent() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.userAgent
}

// SetAvailable makes the token, stream management and poll endpoints answer with 503 while
// false. Published documents (the JWK Set, the metadata) are served regardless.
func (t *TestTransmitter) SetAvailable(available bool) { t.available.Store(available) }

// SetStreamIssuer makes the transmitter create streams with the given issuer instead of its
// own; "" restores its own.
func (t *TestTransmitter) SetStreamIssuer(issuer string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.streamIssuer = issuer
}

// SetLongPollHold is how long a poll request without returnImmediately: true is held while no
// SET is queued. Zero by default: the transmitter then answers at once, as if it did not support
// long polling.
func (t *TestTransmitter) SetLongPollHold(hold time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.longPollHold = hold
}

// ExpireAccessTokens makes the access tokens issued so far invalid: requests with them are
// answered with 401 and the token endpoint issues another token.
func (t *TestTransmitter) ExpireAccessTokens() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.validAccessToken = AccessToken + "-" + newJTI()
}

// Streams are the streams registered at the transmitter, a snapshot.
func (t *TestTransmitter) Streams() []ssf.Claims {
	t.mu.Lock()
	defer t.mu.Unlock()
	streams := make([]ssf.Claims, 0, len(t.streams))
	for _, stream := range t.streams {
		streams = append(streams, copyClaims(stream))
	}
	return streams
}

// AcknowledgedSets are the jtis of the SETs a polling receiver acknowledged, a snapshot.
func (t *TestTransmitter) AcknowledgedSets() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string{}, t.acknowledged...)
}

// ReportedErrors are the errors a polling receiver reported, a snapshot.
func (t *TestTransmitter) ReportedErrors() []ReportedError {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]ReportedError{}, t.reportedErrors...)
}

// VerificationRequests are the states of the verification requests received, a snapshot; "" for
// a request without state.
func (t *TestTransmitter) VerificationRequests() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string{}, t.verificationRequests...)
}

// AddedSubjects are the subjects added to streams, a snapshot.
func (t *TestTransmitter) AddedSubjects() []ssf.Claims {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]ssf.Claims{}, t.addedSubjects...)
}

// RemovedSubjects are the subjects removed from streams, a snapshot.
func (t *TestTransmitter) RemovedSubjects() []ssf.Claims {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]ssf.Claims{}, t.removedSubjects...)
}

// QueuedSetCount is the number of SETs queued and not yet acknowledged.
func (t *TestTransmitter) QueuedSetCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.queued)
}

// QueueSet makes the SET available at the poll endpoint, under its jti.
func (t *TestTransmitter) QueueSet(set string) {
	t.QueueSetWithJTI(ssf.StringMember(ClaimsOf(set), "jti"), set)
}

// QueueSetWithJTI makes the SET available at the poll endpoint under the given jti.
func (t *TestTransmitter) QueueSetWithJTI(jti, set string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i, queued := range t.queued {
		if queued.jti == jti {
			t.queued[i].set = set
			t.wakePolls()
			return
		}
	}
	t.queued = append(t.queued, queuedSET{jti: jti, set: set})
	t.wakePolls()
}

// wakePolls wakes up held poll requests; the mutex must be held.
func (t *TestTransmitter) wakePolls() {
	close(t.queuedChanged)
	t.queuedChanged = make(chan struct{})
}

// Reset forgets streams, queued SETs and what the receiver reported.
func (t *TestTransmitter) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.streams, t.queued, t.acknowledged, t.reportedErrors = nil, nil, nil, nil
	t.verificationRequests, t.addedSubjects, t.removedSubjects = nil, nil, nil
	t.polls.Store(0)
	t.lastPollRequest = nil
	t.longPollHold = 0
	t.available.Store(true)
	t.validAccessToken = AccessToken
	t.streamIssuer = ""
	t.wakePolls()
}

// PublishDocument serves json at the given path of the issuer's host.
func (t *TestTransmitter) PublishDocument(path, body string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.documents[path] = body
}

// RemoveDocument stops serving the document at the path, so that requests for it are answered
// with 404.
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
	t.PublishDocument(realm+jwksPath, string(body))
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

// AddStream registers a stream the way the transmitter does for a create request: assigns the
// identifier, the audience and, for POLL delivery, the poll endpoint. Returns the stream as
// registered.
func (t *TestTransmitter) AddStream(request ssf.Claims) ssf.Claims {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.addStream(request)
}

func (t *TestTransmitter) addStream(request ssf.Claims) ssf.Claims {
	stream := copyClaims(request)
	if ssf.StringMember(stream, "stream_id") == "" {
		stream["stream_id"] = newJTI()
	}
	streamID := stream["stream_id"].(string)
	issuer := t.streamIssuer
	if issuer == "" {
		issuer = t.issuer
	}
	stream["iss"] = issuer
	stream["aud"] = []any{ClientID + "/" + streamID}
	delivered, _ := stream["events_requested"].([]any)
	if delivered == nil {
		delivered = []any{}
	}
	stream["events_delivered"] = delivered
	delivery := copyClaims(ssf.ObjectMember(stream, "delivery"))
	delete(delivery, "authorization_header")
	if ssf.StringMember(delivery, "method") == ssf.PollURI {
		delivery["endpoint_url"] = t.PollURL()
	}
	stream["delivery"] = delivery
	t.streams = append(t.streams, stream)
	return copyClaims(stream)
}

// SetClaims are the claims of a valid SET with a single event whose payload has an
// event_timestamp. eventType is an alias such as CaepSessionRevoked or an event type URI,
// subjectID the sub_id claim, left out if nil.
func (t *TestTransmitter) SetClaims(eventType string, subjectID ssf.Claims) ssf.Claims {
	return t.SetClaimsWithPayload(eventType, subjectID, ssf.Claims{"event_timestamp": time.Now().Unix()})
}

// SetClaimsWithPayload are the claims of a valid SET with a single event and the given payload.
func (t *TestTransmitter) SetClaimsWithPayload(eventType string, subjectID ssf.Claims, payload ssf.Claims) ssf.Claims {
	if payload == nil {
		payload = ssf.Claims{}
	}
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
// 7518: RS256, RS384, RS512, PS256, PS384 or PS512. No minimum key size, unlike
// signing.NewSigner: tests need to sign with keys the receiver has to reject.
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

// Signer is the transmitter's key as a signing.Signer, RS256, for SETs built with ssf.NewSET.
func (t *TestTransmitter) Signer() *signing.Signer {
	signer, err := signing.NewSigner(t.key.Key, jose.RS256, t.key.KeyID)
	if err != nil {
		panic(err)
	}
	return signer
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

// ServeHTTP implements http.Handler: the documents, the token endpoint, the stream management
// endpoints and the poll endpoint. Mount it on an httptest.Server for a real port.
func (t *TestTransmitter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t.requests.Add(1)
	t.mu.Lock()
	t.userAgent = r.Header.Get("User-Agent")
	document, isDocument := t.documents[r.URL.Path]
	valid := t.validAccessToken
	t.mu.Unlock()
	if isDocument {
		respond(w, http.StatusOK, document)
		return
	}
	endpoint, isEndpoint := strings.CutPrefix(r.URL.Path, realm+"/")
	if !isEndpoint {
		respond(w, http.StatusNotFound, "")
		return
	}
	if !t.available.Load() {
		respond(w, http.StatusServiceUnavailable, "")
		return
	}
	body, _ := io.ReadAll(r.Body)
	// the token endpoint of Keycloak, and /token as the emulated authorization server of the
	// conformance suite has it next to the transmitter
	if endpoint == strings.TrimPrefix(tokenPath, "/") || endpoint == "token" {
		t.handleToken(w, r, string(body))
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+valid {
		respond(w, http.StatusUnauthorized, "")
		return
	}
	request := ssf.Claims{}
	if strings.TrimSpace(string(body)) != "" {
		if parsed, err := ssf.ParseClaims(body); err == nil {
			request = parsed
		}
	}
	streamID := r.URL.Query().Get("stream_id")
	if streamID == "" {
		streamID = ssf.StringMember(request, "stream_id")
	}
	switch endpoint {
	case "ssf/streams":
		t.handleStreams(w, r.Method, streamID, request)
	case "ssf/status":
		status := ssf.StringMember(request, "status")
		if status == "" {
			status = ssf.StreamEnabled
		}
		code := http.StatusNotFound
		if streamID != "" && t.findStream(streamID) != nil {
			code = http.StatusOK
		}
		respondJSON(w, code, ssf.Claims{"stream_id": streamID, "status": status})
	case "ssf/verify":
		t.mu.Lock()
		t.verificationRequests = append(t.verificationRequests, stringOf(request["state"]))
		t.mu.Unlock()
		respond(w, http.StatusNoContent, "")
	case strings.TrimPrefix(pollPath, "/"):
		respondJSON(w, http.StatusOK, t.poll(r.Context(), request))
	case "ssf/subjects:add":
		t.mu.Lock()
		t.addedSubjects = append(t.addedSubjects, ssf.ObjectMember(request, "subject"))
		t.mu.Unlock()
		respond(w, http.StatusOK, "")
	case "ssf/subjects:remove":
		t.mu.Lock()
		t.removedSubjects = append(t.removedSubjects, ssf.ObjectMember(request, "subject"))
		t.mu.Unlock()
		respond(w, http.StatusNoContent, "")
	default:
		respond(w, http.StatusNotFound, "")
	}
}

func (t *TestTransmitter) handleToken(w http.ResponseWriter, r *http.Request, form string) {
	values, _ := url.ParseQuery(form)
	user, password, basic := r.BasicAuth()
	authenticated := (basic && user == ClientID && password == ClientSecret) ||
		(values.Get("client_id") == ClientID && values.Get("client_secret") == ClientSecret)
	if !authenticated || values.Get("grant_type") != "client_credentials" {
		respondJSON(w, http.StatusUnauthorized, ssf.Claims{"error": "invalid_client"})
		return
	}
	t.tokens.Add(1)
	t.mu.Lock()
	token := t.validAccessToken
	t.mu.Unlock()
	respondJSON(w, http.StatusOK, ssf.Claims{"access_token": token, "token_type": "Bearer", "expires_in": 300})
}

func (t *TestTransmitter) handleStreams(w http.ResponseWriter, method, streamID string, request ssf.Claims) {
	switch method {
	case http.MethodGet:
		if streamID == "" {
			streams := t.Streams()
			list := make([]any, 0, len(streams))
			for _, stream := range streams {
				list = append(list, stream)
			}
			body, _ := json.Marshal(list)
			respond(w, http.StatusOK, string(body))
			return
		}
		if stream := t.findStream(streamID); stream != nil {
			respondJSON(w, http.StatusOK, stream)
			return
		}
		respond(w, http.StatusNotFound, "")
	case http.MethodPost:
		t.mu.Lock()
		defer t.mu.Unlock()
		if len(t.streams) > 0 {
			respondJSON(w, http.StatusConflict, ssf.Claims{"error": "stream_error", "error_description": "Only one stream per receiver is allowed"})
			return
		}
		respondJSON(w, http.StatusCreated, t.addStream(request))
	case http.MethodPatch, http.MethodPut:
		t.mu.Lock()
		defer t.mu.Unlock()
		updated := t.findStreamLocked(streamID)
		if updated == nil {
			respond(w, http.StatusNotFound, "")
			return
		}
		for name, value := range request {
			updated[name] = value
		}
		t.removeStreamLocked(streamID)
		respondJSON(w, http.StatusOK, t.addStream(updated))
	case http.MethodDelete:
		t.mu.Lock()
		defer t.mu.Unlock()
		if t.findStreamLocked(streamID) == nil {
			respond(w, http.StatusNotFound, "")
			return
		}
		t.removeStreamLocked(streamID)
		respond(w, http.StatusNoContent, "")
	default:
		respond(w, http.StatusMethodNotAllowed, "")
	}
}

func (t *TestTransmitter) poll(ctx context.Context, request ssf.Claims) ssf.Claims {
	t.polls.Add(1)
	maxEvents := 10
	if n, ok := ssf.Int64(request["maxEvents"]); ok {
		maxEvents = int(n)
	}
	returnImmediately, _ := request["returnImmediately"].(bool)
	t.mu.Lock()
	t.lastPollRequest = copyClaims(request)
	hold := t.longPollHold
	for _, jti := range ssf.Strings(request["ack"]) {
		if t.removeQueuedLocked(jti) {
			t.acknowledged = append(t.acknowledged, jti)
		}
	}
	for jti, report := range ssf.ObjectMember(request, "setErrs") {
		t.removeQueuedLocked(jti)
		t.reportedErrors = append(t.reportedErrors, ReportedError{JTI: jti, Code: ssf.StringMember(ssf.Object(report), "err"),
			Description: ssf.StringMember(ssf.Object(report), "description")})
	}
	t.mu.Unlock()
	// a long poll (returnImmediately false or absent, RFC 8936 section 2.5) is held until a SET
	// is queued, the hold time elapses or the receiver gives up
	if !returnImmediately && maxEvents > 0 && hold > 0 {
		deadline := time.After(hold)
	waiting:
		for {
			t.mu.Lock()
			queued, changed := len(t.queued), t.queuedChanged
			t.mu.Unlock()
			if queued > 0 {
				break
			}
			select {
			case <-changed:
			case <-deadline:
				break waiting
			case <-ctx.Done():
				break waiting
			}
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	sets := ssf.Claims{}
	for i, queued := range t.queued {
		if i >= maxEvents {
			break
		}
		sets[queued.jti] = queued.set
	}
	return ssf.Claims{"sets": sets, "moreAvailable": len(t.queued) > len(sets)}
}

func (t *TestTransmitter) removeQueuedLocked(jti string) bool {
	for i, queued := range t.queued {
		if queued.jti == jti {
			t.queued = append(t.queued[:i], t.queued[i+1:]...)
			return true
		}
	}
	return false
}

func (t *TestTransmitter) findStream(streamID string) ssf.Claims {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.findStreamLocked(streamID)
}

func (t *TestTransmitter) findStreamLocked(streamID string) ssf.Claims {
	for _, stream := range t.streams {
		if ssf.StringMember(stream, "stream_id") == streamID {
			return copyClaims(stream)
		}
	}
	return nil
}

func (t *TestTransmitter) removeStreamLocked(streamID string) {
	kept := t.streams[:0]
	for _, stream := range t.streams {
		if ssf.StringMember(stream, "stream_id") != streamID {
			kept = append(kept, stream)
		}
	}
	t.streams = kept
}

func respond(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func respondJSON(w http.ResponseWriter, status int, body ssf.Claims) {
	encoded, _ := json.Marshal(body)
	respond(w, status, string(encoded))
}

func stringOf(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	}
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func copyClaims(claims ssf.Claims) ssf.Claims {
	copied := make(ssf.Claims, len(claims))
	for name, value := range claims {
		copied[name] = value
	}
	return copied
}

// ClientFor is an *http.Client that answers requests for the hosts of the given transmitters
// in-process, each from its handler, and refuses every other host, so a test never reaches the
// network. TestTransmitter.Client is one for a single transmitter; a receiver with several
// transmitters gets one for all of them.
func ClientFor(transmitters ...*TestTransmitter) *http.Client {
	return &http.Client{Transport: &inProcess{transmitters: transmitters}}
}

// inProcess is an http.RoundTripper that routes requests to the transmitter whose host they
// name.
type inProcess struct{ transmitters []*TestTransmitter }

func (p *inProcess) RoundTrip(r *http.Request) (*http.Response, error) {
	for _, transmitter := range p.transmitters {
		if strings.HasPrefix(transmitter.issuer, r.URL.Scheme+"://"+r.URL.Host+"/") {
			return serve(transmitter, r)
		}
	}
	return nil, fmt.Errorf("ssftest: no route to %s://%s, the test transmitters are %v", r.URL.Scheme, r.URL.Host, p.issuers())
}

func (p *inProcess) issuers() []string {
	issuers := make([]string, 0, len(p.transmitters))
	for _, transmitter := range p.transmitters {
		issuers = append(issuers, transmitter.issuer)
	}
	return issuers
}

func serve(transmitter *TestTransmitter, r *http.Request) (*http.Response, error) {
	if r.Body == nil {
		r.Body = http.NoBody
	}
	recorder := &responseRecorder{header: http.Header{}, status: http.StatusOK}
	transmitter.ServeHTTP(recorder, r)
	if err := r.Context().Err(); err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: recorder.status, Status: fmt.Sprintf("%d %s", recorder.status, http.StatusText(recorder.status)),
		Header: recorder.header, Body: io.NopCloser(strings.NewReader(recorder.body.String())),
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

func newJTI() string { return ssf.NewJTI() }

// TB is the part of testing.TB that Eventually and During need.
type TB interface {
	Helper()
	Fatalf(format string, args ...any)
}

// Eventually waits until condition holds, polling it every 10 milliseconds for at most timeout;
// the Eventually of the Java and .NET tests. It fails the test with what if it does not hold in
// time.
func Eventually(t TB, timeout time.Duration, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("Timed out waiting for: %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// During checks that condition keeps holding for duration, polling it every 10 milliseconds. It
// fails the test with what otherwise.
func During(t TB, duration time.Duration, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(duration)
	for time.Now().Before(deadline) {
		if !condition() {
			t.Fatalf("Stopped holding: %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
