package receiver_test

// SsfPushHandlerTests of the Java library, plus the http.Handler.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/easyssf/easyssf-go/receiver"
	"github.com/easyssf/easyssf-go/ssftest"
)

const secret = "Bearer s3cr3t"

// recorder counts the SETs it handled.
type recorder struct{ count atomic.Int32 }

func (r *recorder) Handle(context.Context, *receiver.Context) error {
	r.count.Add(1)
	return nil
}

func processor(t *testing.T, transmitter *ssftest.TestTransmitter, handlers ...receiver.Handler) *receiver.Processor {
	t.Helper()
	return receiver.NewProcessor(verifier(t, transmitter), receiver.NewInMemoryJTIDedupStore(10, 0, nil), receiver.ProcessorOptions{}).
		AddHandler(handlers...)
}

func pushHandler(t *testing.T, transmitter *ssftest.TestTransmitter, r *recorder) *receiver.PushHandler {
	return receiver.NewPushHandler(processor(t, transmitter, r), secret)
}

func errorCode(t *testing.T, response receiver.PushResponse) string {
	t.Helper()
	var body map[string]string
	if err := json.Unmarshal(response.Body, &body); err != nil {
		t.Fatalf("no error document: %v", err)
	}
	return body["err"]
}

func TestAcceptsAndHandlesSET(t *testing.T) {
	transmitter := ssftest.New()
	r := &recorder{}
	response := pushHandler(t, transmitter, r).Handle(ctx, secret, []byte(transmitter.Set("CaepSessionRevoked", alice(transmitter))))
	if response.Status != 202 || !response.IsAccepted() || response.Body != nil || r.count.Load() != 1 {
		t.Fatalf("%+v", response)
	}
}

func TestAcceptsDuplicateWithoutHandlingItAgain(t *testing.T) {
	transmitter := ssftest.New()
	r := &recorder{}
	handler := pushHandler(t, transmitter, r)
	set := []byte(transmitter.Set("CaepSessionRevoked", alice(transmitter)))
	handler.Handle(ctx, secret, set)
	if handler.Handle(ctx, secret, set).Status != 202 || r.count.Load() != 1 {
		t.Fatal("duplicate accepted and skipped")
	}
}

func TestRejectsTransmitterThatDoesNotAuthenticate(t *testing.T) {
	transmitter := ssftest.New()
	r := &recorder{}
	handler := pushHandler(t, transmitter, r)
	set := []byte(transmitter.Set("CaepSessionRevoked", alice(transmitter)))
	for _, authorization := range []string{"", "Bearer wrong", "bearer s3cr3t"} {
		response := handler.Handle(ctx, authorization, set)
		if response.Status != 401 || errorCode(t, response) != "authentication_failed" {
			t.Errorf("%q: %+v", authorization, response)
		}
	}
	if r.count.Load() != 0 {
		t.Fatal("nothing handled")
	}
	// without an expected header anything goes
	open := receiver.NewPushHandler(processor(t, transmitter, r), "")
	if open.Handle(ctx, "", set).Status != 202 {
		t.Fatal("open")
	}
}

func TestRejectsInvalidSETWithErrorDocument(t *testing.T) {
	transmitter := ssftest.New()
	r := &recorder{}
	handler := pushHandler(t, transmitter, r)
	claims := transmitter.SetClaims("CaepSessionRevoked", alice(transmitter))
	claims["aud"] = "https://other.example"
	response := handler.Handle(ctx, secret, []byte(transmitter.SignSET(claims)))
	if response.Status != 400 || errorCode(t, response) != "invalid_audience" || !strings.Contains(string(response.Body), "not addressed") {
		t.Fatalf("%+v", response)
	}
	if errorCode(t, handler.Handle(ctx, secret, []byte("garbage"))) != "invalid_request" {
		t.Fatal("garbage")
	}
	response = handler.Handle(ctx, secret, []byte{0xff, 0xfe})
	if response.Status != 400 || errorCode(t, response) != "invalid_request" {
		t.Fatalf("%+v", response)
	}
	if r.count.Load() != 0 {
		t.Fatal("nothing handled")
	}
}

func TestRejectsOversizedSET(t *testing.T) {
	transmitter := ssftest.New()
	response := pushHandler(t, transmitter, &recorder{}).Handle(ctx, secret, bytes.Repeat([]byte("a"), receiver.MaxSETSize+1))
	if response.Status != 413 || errorCode(t, response) != "invalid_request" {
		t.Fatalf("%+v", response)
	}
}

func TestAsksForRedeliveryWhenHandlerFails(t *testing.T) {
	transmitter := ssftest.New()
	failing := receiver.HandlerFunc(func(context.Context, *receiver.Context) error { return errors.New("nope") })
	handler := receiver.NewPushHandler(processor(t, transmitter, failing), secret)
	response := handler.Handle(ctx, secret, []byte(transmitter.Set("CaepSessionRevoked", alice(transmitter))))
	if response.Status != 500 || response.Body != nil {
		t.Fatalf("%+v", response)
	}
}

func TestAsksForRedeliveryWhileTransmitterKeysAreUnavailable(t *testing.T) {
	transmitter := ssftest.New()
	transmitter.RemoveDocument("/realms/test/protocol/openid-connect/certs")
	handler := pushHandler(t, transmitter, &recorder{})
	set := []byte(transmitter.Set("CaepSessionRevoked", alice(transmitter)))
	if handler.Handle(ctx, secret, set).Status != 503 {
		t.Fatal("503 while unavailable")
	}
	transmitter.PublishJWKS(transmitter.Key())
	if handler.Handle(ctx, secret, set).Status != 202 {
		t.Fatal("202 once available")
	}
}

func TestAuthenticatesEveryTransmitterWithItsOwnHeader(t *testing.T) {
	transmitter := ssftest.New()
	handler := receiver.NewPushHandlerByIssuer(processor(t, transmitter, &recorder{}), func(issuer string) string {
		if issuer == transmitter.Issuer() {
			return "Bearer mine"
		}
		return ""
	})
	set := []byte(transmitter.Set("CaepSessionRevoked", alice(transmitter)))
	if handler.Handle(ctx, secret, set).Status != 401 || handler.Handle(ctx, "Bearer mine", set).Status != 202 {
		t.Fatal("own header")
	}
	// a SET of an unknown issuer needs no header to be rejected as invalid_issuer
	claims := transmitter.SetClaims("CaepSessionRevoked", alice(transmitter))
	claims["iss"] = "https://unknown.example"
	response := handler.Handle(ctx, "", []byte(transmitter.SignSET(claims)))
	if response.Status != 400 || errorCode(t, response) != "invalid_issuer" {
		t.Fatalf("%+v", response)
	}
}

func TestServesPushEndpointOverHTTP(t *testing.T) {
	transmitter := ssftest.New()
	r := &recorder{}
	server := httptest.NewServer(pushHandler(t, transmitter, r))
	defer server.Close()
	post := func(authorization, body string) *http.Response {
		request, _ := http.NewRequest(http.MethodPost, server.URL, strings.NewReader(body))
		request.Header.Set("Authorization", authorization)
		request.Header.Set("Content-Type", "application/secevent+jwt")
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		return response
	}
	if response := post(secret, transmitter.Set("CaepSessionRevoked", alice(transmitter))); response.StatusCode != http.StatusAccepted || r.count.Load() != 1 {
		t.Fatalf("%d", response.StatusCode)
	}
	response := post(secret, "garbage")
	if response.StatusCode != http.StatusBadRequest || response.Header.Get("Content-Type") != "application/json" || response.Header.Get("Content-Language") != "en" {
		t.Fatalf("%d %v", response.StatusCode, response.Header)
	}
	if response, _ := http.Get(server.URL); response.StatusCode != http.StatusMethodNotAllowed {
		t.Fatal("POST only")
	}
}
