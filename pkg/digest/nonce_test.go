package digest

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNonceStoreIncrementBasic(t *testing.T) {
	s := newNonceStore(4, time.Hour)
	assert.Equal(t, 1, s.increment("a"))
	assert.Equal(t, 2, s.increment("a"))
	assert.Equal(t, 1, s.increment("b"))
	assert.Equal(t, 3, s.increment("a"))
	assert.Equal(t, 2, s.size())
	assert.Equal(t, 3, s.count("a"))
	assert.Equal(t, 1, s.count("b"))
	assert.Equal(t, 0, s.count("missing"))
}

func TestNonceStoreEvictsOldestWhenFull(t *testing.T) {
	s := newNonceStore(3, time.Hour)
	// Drive a manual clock so recency ordering is deterministic.
	base := time.Unix(0, 0)
	tick := int64(0)
	s.clock = func() time.Time {
		tick++
		return base.Add(time.Duration(tick) * time.Second)
	}

	s.increment("a") // tick 1
	s.increment("b") // tick 2
	s.increment("c") // tick 3
	assert.Equal(t, 3, s.size())

	// Touch "a" and "b" so "c" is oldest.
	s.increment("a") // tick 4
	s.increment("b") // tick 5

	// Insert "d" — capacity full, "c" must be evicted.
	s.increment("d") // tick 6
	assert.Equal(t, 3, s.size())
	assert.Equal(t, 0, s.count("c"), "oldest entry 'c' should have been evicted")
	assert.Equal(t, 2, s.count("a"))
	assert.Equal(t, 2, s.count("b"))
	assert.Equal(t, 1, s.count("d"))
}

func TestNonceStoreExpiresByTTL(t *testing.T) {
	s := newNonceStore(16, 10*time.Second)
	now := time.Unix(1000, 0)
	s.clock = func() time.Time { return now }

	s.increment("a")
	s.increment("b")
	assert.Equal(t, 2, s.size())

	// Jump past the TTL; next increment should sweep both.
	now = now.Add(30 * time.Second)
	s.increment("c")
	// "a" and "b" were both stale and swept before "c" was added.
	assert.Equal(t, 1, s.size())
	assert.Equal(t, 0, s.count("a"))
	assert.Equal(t, 0, s.count("b"))
	assert.Equal(t, 1, s.count("c"))
}

func TestNonceStoreReset(t *testing.T) {
	s := newNonceStore(4, time.Hour)
	s.increment("a")
	s.increment("a")
	s.increment("a")
	assert.Equal(t, 3, s.count("a"))
	s.reset("a")
	assert.Equal(t, 0, s.count("a"))
	// Next increment starts fresh.
	assert.Equal(t, 1, s.increment("a"))
}

func TestNonceStoreZeroDefaults(t *testing.T) {
	s := newNonceStore(0, 0)
	assert.Equal(t, DefaultNonceCapacity, s.cap)
	assert.Equal(t, DefaultNonceTTL, s.ttl)
}

// TestTransportNonceStoreConcurrency exercises the thread-safety of the
// Increment path under heavy concurrent use and asserts the final
// per-nonce count is exactly the number of writers (no lost updates).
func TestTransportNonceStoreConcurrency(t *testing.T) {
	trans := NewTransport("u", "p", nil)
	const (
		nonces  = 8
		workers = 32
		perKey  = 50
	)
	var wg sync.WaitGroup
	wg.Add(workers * nonces)
	for w := 0; w < workers; w++ {
		for n := 0; n < nonces; n++ {
			key := fmt.Sprintf("nonce-%d", n)
			go func(k string) {
				defer wg.Done()
				for i := 0; i < perKey; i++ {
					trans.Increment(k)
				}
			}(key)
		}
	}
	wg.Wait()

	require.Equal(t, nonces, trans.TrackedNonces())
	for n := 0; n < nonces; n++ {
		key := fmt.Sprintf("nonce-%d", n)
		assert.Equal(t, workers*perKey, trans.NonceCount(key), "key=%s", key)
	}
}
