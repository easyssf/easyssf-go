package receiver

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/easyssf/easyssf-go/ssf"
)

// Push delivery (RFC 8935): header and body in, status and body out, plus the http.Handler.

// MaxSETSize is the maximum size of a SET in bytes. An endpoint does not need to read more than
// one byte beyond it.
const MaxSETSize = 256 * 1024

const (
	// PushContentType is the content type of an error document.
	PushContentType = "application/json"
	// PushContentLanguage is the language of the description in the error document, sent as
	// Content-Language header (RFC 8935, section 2.3).
	PushContentLanguage = "en"

	authenticationFailed = "authentication_failed"
)

// PushResponse is the response to a push request (RFC 8935, section 2.2 to 2.4).
type PushResponse struct {
	// Status is the HTTP status.
	Status int
	// Body is the JSON error document, nil if the response has no body; send it with the
	// PushContentType and PushContentLanguage headers.
	Body []byte
}

// IsAccepted reports whether the SET was accepted.
func (r PushResponse) IsAccepted() bool { return r.Status == http.StatusAccepted }

func pushError(status int, code, description string) PushResponse {
	body, _ := json.Marshal(map[string]string{"err": code, "description": description})
	return PushResponse{Status: status, Body: body}
}

// ExpectedAuthorizationHeaders is the Authorization header a transmitter has to send, by the
// issuer of its SETs; "" for none.
type ExpectedAuthorizationHeaders func(issuer string) string

// PushHandler handles SETs delivered using HTTP push (RFC 8935). It is an http.Handler for the
// endpoint the transmitter posts SETs to; frameworks without http.Handler adapters call Handle
// with the Authorization header and the body and send the returned response.
//
// A SET is verified and handled before it is acknowledged with 202 Accepted. Invalid SETs are
// rejected with 400 Bad Request and an error document. When the SET could not be processed for a
// reason the transmitter is not responsible for (its keys are temporarily not retrievable, an
// event handler failed) a 5xx status asks it to deliver the SET again.
//
// The handlers run with a context that is not cancelled when the transmitter disconnects, so a
// dropped request does not cancel them; a panic becomes a 500 and the dedup store releases the
// claim after its lease.
type PushHandler struct {
	processor *Processor
	fixed     string
	byIssuer  ExpectedAuthorizationHeaders
	metrics   Metrics
	log       *slog.Logger
}

// NewPushHandler is a handler that expects exactly this Authorization header, or none if "".
func NewPushHandler(processor *Processor, expectedAuthorizationHeader string) *PushHandler {
	return &PushHandler{processor: processor, fixed: strings.TrimSpace(expectedAuthorizationHeader),
		metrics: processor.metrics, log: processor.log}
}

// NewPushHandlerByIssuer is for a receiver with several transmitters: the Authorization header a
// transmitter has to send is looked up by the issuer of the SET, which is read before the SET is
// verified.
func NewPushHandlerByIssuer(processor *Processor, expected ExpectedAuthorizationHeaders) *PushHandler {
	return &PushHandler{processor: processor, byIssuer: expected, metrics: processor.metrics, log: processor.log}
}

// Processor is the processor the SETs go to.
func (h *PushHandler) Processor() *Processor { return h.processor }

// Handle handles a push request: the Authorization header of the request ("" if none) and the
// body, the SET in JWS compact serialization.
func (h *PushHandler) Handle(ctx context.Context, authorizationHeader string, body []byte) PushResponse {
	if h.byIssuer == nil && !authenticated(h.fixed, authorizationHeader) {
		h.metrics.SetReceived("", ssf.Push, OutcomeUnauthenticated)
		return pushError(http.StatusUnauthorized, authenticationFailed, "The transmitter could not be authenticated")
	}
	if len(body) > MaxSETSize {
		return pushError(http.StatusRequestEntityTooLarge, string(InvalidRequest), "The SET is too large")
	}
	if !utf8.Valid(body) {
		return pushError(http.StatusBadRequest, string(InvalidRequest), "The SET is not UTF-8")
	}
	encodedSET := strings.TrimSpace(string(body))
	if h.byIssuer != nil {
		issuer := UnverifiedIssuer(encodedSET)
		expected := ""
		if issuer != "" {
			expected = h.byIssuer(issuer)
		}
		if !authenticated(expected, authorizationHeader) {
			h.metrics.SetReceived(issuer, ssf.Push, OutcomeUnauthenticated)
			return pushError(http.StatusUnauthorized, authenticationFailed, "The transmitter could not be authenticated")
		}
	}
	_, err := h.processor.Process(ctx, encodedSET, ssf.Push)
	switch {
	case err == nil:
		return PushResponse{Status: http.StatusAccepted}
	case RejectionOf(err) != nil:
		rejected := RejectionOf(err)
		h.log.Debug("Rejecting SET", "code", string(rejected.Code), "description", rejected.Description)
		return pushError(http.StatusBadRequest, string(rejected.Code), rejected.Description)
	case IsTransmitterUnavailable(err):
		h.log.Warn("Could not verify SET, asking the transmitter to deliver it again", "error", err)
		return PushResponse{Status: http.StatusServiceUnavailable}
	case errors.Is(err, ErrInProgress):
		// temporary: the transmitter delivers the SET again
		return PushResponse{Status: http.StatusServiceUnavailable}
	default:
		var storeError *StoreError
		if errors.As(err, &storeError) {
			h.log.Error("The dedup store failed, asking the transmitter to deliver the SET again", "error", err)
		}
		// a HandlingError was logged per handler
		return PushResponse{Status: http.StatusInternalServerError}
	}
}

// ServeHTTP implements http.Handler: POST with the SET as body, application/secevent+jwt. Mount
// it at the push endpoint path (/ssf/push by default) with a POST-only route, or let it answer
// 405 to other methods itself.
func (h *PushHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxSETSize+1))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// detached from the request: a transmitter that disconnects does not cancel the handlers
	response := h.Handle(context.WithoutCancel(r.Context()), r.Header.Get("Authorization"), body)
	if response.Body != nil {
		w.Header().Set("Content-Type", PushContentType)
		w.Header().Set("Content-Language", PushContentLanguage)
	}
	w.WriteHeader(response.Status)
	if response.Body != nil {
		_, _ = w.Write(response.Body)
	}
}

func authenticated(expected, given string) bool {
	if expected == "" {
		return true
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(given)) == 1
}
