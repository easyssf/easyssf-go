package sqlstore_test

// AbstractJdbcSharedReceiversTests of the Java library: two instances of a receiver on one
// database. On SQLite in memory.

import (
	"context"
	"database/sql"
	"sync/atomic"
	"testing"
	"time"

	"github.com/easyssf/easyssf-go/receiver"
	"github.com/easyssf/easyssf-go/receiver/sqlstore"
	"github.com/easyssf/easyssf-go/ssf"
	"github.com/easyssf/easyssf-go/ssftest"
)

func sharedStores(t *testing.T, config receiver.Config) *sqlstore.Stores {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	stores := sqlstore.NewStores(sqlstore.NewOperations(db, sqlstore.SQLite), config)
	must(t, stores.PrepareTables(ctx))
	return stores
}

func pollConfig(transmitter *ssftest.TestTransmitter) receiver.Config {
	config := receiver.DefaultConfig()
	config.TransmitterIssuer = transmitter.Issuer()
	config.ExpectedAudience = ssftest.Audience
	config.DeliveryMethod = "poll"
	config.TransmitterAccessToken = ssftest.AccessToken
	config.Poll.EndpointURL = transmitter.PollURL()
	config.Poll.Interval = receiver.D(50 * time.Millisecond)
	config.Dedup.Lease = receiver.D(300 * time.Millisecond)
	return config
}

func counting(counter *atomic.Int32) receiver.Handler {
	return receiver.HandlerFunc(func(context.Context, *receiver.Context) error {
		counter.Add(1)
		return nil
	})
}

func TestSetIsHandledOnceAndAcknowledgedByWhicheverInstancePollsNext(t *testing.T) {
	transmitter := ssftest.New()
	config := pollConfig(transmitter)
	stores := sharedStores(t, config)
	var handled atomic.Int32
	for i := 0; i < 2; i++ {
		options := append(stores.Options(), receiver.WithHTTPClient(transmitter.Client), receiver.WithHandler(counting(&handled)))
		rcv, err := receiver.New(config, options...)
		must(t, err)
		rcv.Start(ctx)
		defer rcv.Stop(ctx)
	}
	transmitter.QueueSet(transmitter.Set("CaepSessionRevoked", ssf.IssSub(transmitter.Issuer(), "alice")))
	ssftest.Eventually(t, 5*time.Second, "the acknowledgement", func() bool { return len(transmitter.AcknowledgedSets()) == 1 })
	ssftest.During(t, 300*time.Millisecond, "handled once", func() bool { return handled.Load() == 1 })
	// a redelivery later is handled by no instance
	transmitter.QueueSet(transmitter.Set("CaepSessionRevoked", ssf.IssSub(transmitter.Issuer(), "bob")))
	ssftest.Eventually(t, 5*time.Second, "the second acknowledgement", func() bool { return len(transmitter.AcknowledgedSets()) == 2 })
	if handled.Load() != 2 {
		t.Fatalf("%d", handled.Load())
	}
}

func TestSetBeingHandledByOneInstanceIsNeitherHandledNorAcknowledgedByAnother(t *testing.T) {
	transmitter := ssftest.New()
	config := pollConfig(transmitter)
	stores := sharedStores(t, config)
	release := make(chan struct{})
	var entered, otherHandled atomic.Int32
	slowHandler := receiver.HandlerFunc(func(context.Context, *receiver.Context) error {
		entered.Add(1)
		<-release
		return nil
	})
	slow, err := receiver.New(config, append(stores.Options(), receiver.WithHTTPClient(transmitter.Client), receiver.WithHandler(slowHandler))...)
	must(t, err)
	other, err := receiver.New(config, append(stores.Options(), receiver.WithHTTPClient(transmitter.Client), receiver.WithHandler(counting(&otherHandled)))...)
	must(t, err)
	slow.Start(ctx)
	defer slow.Stop(ctx)
	transmitter.QueueSet(transmitter.Set("CaepSessionRevoked", ssf.IssSub(transmitter.Issuer(), "alice")))
	ssftest.Eventually(t, 5*time.Second, "the slow handler", func() bool { return entered.Load() == 1 })
	other.Start(ctx)
	defer other.Stop(ctx)
	// the other instance polls the SET too, but leaves it alone while the claim is renewed
	ssftest.During(t, 500*time.Millisecond, "left alone", func() bool {
		return otherHandled.Load() == 0 && len(transmitter.AcknowledgedSets()) == 0
	})
	close(release)
	ssftest.Eventually(t, 5*time.Second, "the acknowledgement", func() bool { return len(transmitter.AcknowledgedSets()) == 1 })
	if otherHandled.Load() != 0 {
		t.Fatal("handled by the other")
	}
}

func TestErrorReportOfOneInstanceLeavesWithTheNextPollOfAnother(t *testing.T) {
	transmitter := ssftest.New()
	config := pollConfig(transmitter)
	stores := sharedStores(t, config)
	first, err := receiver.New(config, append(stores.Options(), receiver.WithHTTPClient(transmitter.Client))...)
	must(t, err)
	second, err := receiver.New(config, append(stores.Options(), receiver.WithHTTPClient(transmitter.Client))...)
	must(t, err)
	claims := transmitter.SetClaims("CaepSessionRevoked", ssf.IssSub(transmitter.Issuer(), "alice"))
	claims["aud"] = "https://other.example"
	transmitter.QueueSet(transmitter.SignSET(claims))
	// the first instance polls once by hand and records the error
	if _, err := first.Transmitters()[0].Poller.PollNow(ctx); err != nil {
		t.Fatal(err)
	}
	if len(transmitter.ReportedErrors()) != 1 {
		t.Fatal("reported with the acknowledging request of the same poll")
	}
	// a report recorded by the first instance's store reaches the transmitter with the second's poll
	must(t, stores.PollAckStore().Record(ctx, transmitter.Issuer(), receiver.AckError("stale", receiver.InvalidRequest, "")))
	second.Start(ctx)
	defer second.Stop(ctx)
	ssftest.Eventually(t, 5*time.Second, "the stale report", func() bool {
		for _, reported := range transmitter.ReportedErrors() {
			if reported.JTI == "stale" {
				return true
			}
		}
		return false
	})
}
