package sqlstore

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// ExpiringStore is a store whose rows expire and are purged, by the store itself when it is
// written to and periodically by Cleanup.
type ExpiringStore interface {
	// PurgeExpired deletes the rows that expired and returns how many.
	PurgeExpired(ctx context.Context) (int64, error)
	// Name is the name of the store, for the log.
	Name() string
}

// Cleanup purges the expired rows of the stores periodically, so that they do not linger in a
// receiver that gets no events for a while. Either call PurgeExpired from the scheduler of the
// application, or Start to run it in a goroutine of its own.
type Cleanup struct {
	// Log is where the cleanup logs; discarded if nil.
	Log *slog.Logger

	stores   []ExpiringStore
	interval time.Duration
	mu       sync.Mutex
	cancel   context.CancelFunc
	done     chan struct{}
}

// NewCleanup is a cleanup of the stores every interval; the periodic cleanup is off when the
// interval is zero.
func NewCleanup(stores []ExpiringStore, interval time.Duration) *Cleanup {
	return &Cleanup{stores: stores, interval: interval}
}

// Interval is how often the stores are purged.
func (c *Cleanup) Interval() time.Duration { return c.interval }

// IsEnabled reports whether the periodic cleanup runs when started: the interval is positive
// and there is a store to purge.
func (c *Cleanup) IsEnabled() bool { return c.interval > 0 && len(c.stores) > 0 }

// IsRunning reports whether the periodic cleanup is running.
func (c *Cleanup) IsRunning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cancel != nil
}

// PurgeExpired purges the expired rows of all stores once; a store that fails is logged and
// skipped. Returns the number of rows deleted.
func (c *Cleanup) PurgeExpired(ctx context.Context) int64 {
	log := c.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	var deleted int64
	for _, store := range c.stores {
		count, err := store.PurgeExpired(ctx)
		if err != nil {
			log.Warn("Could not purge the expired rows", "store", store.Name(), "error", err)
			continue
		}
		deleted += count
	}
	if deleted > 0 {
		log.Debug("Purged expired rows", "deleted", deleted)
	}
	return deleted
}

// Start starts purging periodically in the background, if enabled, until ctx is cancelled or
// Stop is called.
func (c *Cleanup) Start(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancel != nil || !c.IsEnabled() {
		return
	}
	ctx, c.cancel = context.WithCancel(ctx)
	c.done = make(chan struct{})
	go func(done chan struct{}) {
		defer close(done)
		ticker := time.NewTicker(c.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.PurgeExpired(ctx)
			}
		}
	}(c.done)
}

// Stop stops the periodic cleanup.
func (c *Cleanup) Stop() {
	c.mu.Lock()
	cancel, done := c.cancel, c.done
	c.cancel, c.done = nil, nil
	c.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}
