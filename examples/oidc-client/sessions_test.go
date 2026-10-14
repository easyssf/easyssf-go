package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/easyssf/easyssf-go/receiver"
	"github.com/easyssf/easyssf-go/ssf"
	"github.com/easyssf/easyssf-go/ssftest"
)

const idp = "https://idp.example"

func loggedIn(t *testing.T, sessions *Sessions, sub, sid string) *Session {
	t.Helper()
	recorder := httptest.NewRecorder()
	session := sessions.Start(recorder)
	session.User = &LoggedInUser{Issuer: idp, Subject: sub, SID: sid, Username: sub, Claims: ssf.Claims{"iss": idp, "sub": sub, "sid": sid}}
	session.LoggedInAt = time.Now().Add(-time.Minute)
	return session
}

func TestSessionRevokedEventEndsTheLocalSession(t *testing.T) {
	transmitter := ssftest.New()
	sessions := NewSessions()
	loggedIn(t, sessions, "alice", "s1")
	loggedIn(t, sessions, "alice", "s2")
	loggedIn(t, sessions, "bob", "s3")
	config := receiver.DefaultConfig()
	config.TransmitterIssuer = transmitter.Issuer()
	config.ExpectedAudience = ssftest.Audience
	rcv, err := receiver.New(config, receiver.WithHTTPClient(transmitter.Client), receiver.WithSessionTerminator(sessions))
	if err != nil {
		t.Fatal(err)
	}
	set := []byte(transmitter.Set("CaepSessionRevoked", ssf.Complex(ssf.IssSub(idp, "alice"), ssf.Opaque("s1"))))
	if rcv.PushHandler().Handle(context.Background(), "", set).Status != 202 || len(sessions.sessions) != 2 {
		t.Fatal("s1 ended")
	}
	set = []byte(transmitter.Set("CaepCredentialChange", ssf.Complex(ssf.IssSub(idp, "alice"), ssf.Opaque("s2"))))
	if rcv.PushHandler().Handle(context.Background(), "", set).Status != 202 || len(sessions.sessions) != 1 {
		t.Fatal("all of alice ended")
	}
}

func TestRevocationCheckEndsASessionRevokedAfterTheLogin(t *testing.T) {
	sessions := NewSessions()
	session := loggedIn(t, sessions, "alice", "s1")
	store := receiver.NewInMemoryTokenRevocationStore(0, nil)
	handler := sessions.RevocationCheck(store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(&http.Cookie{Name: cookieName, Value: session.ID})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != 200 {
		t.Fatal("alive")
	}
	_ = store.RevokeSubject(context.Background(), idp, "alice", time.Now())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != 302 || sessions.Get(request) != nil {
		t.Fatalf("%d", recorder.Code)
	}
}
