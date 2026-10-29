package receiver

import (
	"context"
	"testing"
)

func TestStartMakesTheRegistrarWakeThePollerOnce(t *testing.T) {
	// a registrar that looks like it is running, so that Start does not register anything
	registrar := &StreamRegistrar{stream: NewReceiverStream(), cancel: func() {}, ended: make(chan struct{})}
	transmitter := &Transmitter{Registrar: registrar, Poller: &Poller{wake: make(chan struct{}, 1)}}
	for range 3 {
		transmitter.Start(context.Background())
	}
	registrar.mu.Lock()
	defer registrar.mu.Unlock()
	if len(registrar.listeners) != 1 {
		t.Fatalf("%d listeners after three starts", len(registrar.listeners))
	}
}
