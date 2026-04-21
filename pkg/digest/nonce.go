package digest

import (
	"container/list"
	"sync"
	"time"
)

// Defaults for the bounded nonce counter. A long-lived Transport talking to a
// server that rotates nonces will accumulate one entry per nonce otherwise;
// these values cap the memory usage without hurting nc accuracy for any
// nonce the server is actively using.
const (
	DefaultNonceCapacity = 1024
	DefaultNonceTTL      = 30 * time.Minute
)

// nonceStore is a bounded LRU+TTL counter for the per-nonce request count
// (nc) used by digest authentication. Entries are evicted when either the
// capacity is reached (least-recently-seen first) or an entry has gone
// unused for longer than the TTL.
type nonceStore struct {
	mu    sync.Mutex
	cap   int
	ttl   time.Duration
	clock func() time.Time // overridable for testing
	order *list.List       // front = most recent; each Element holds *nonceEntry
	m     map[string]*list.Element
}

type nonceEntry struct {
	nonce    string
	nc       int
	lastSeen time.Time
}

func newNonceStore(capacity int, ttl time.Duration) *nonceStore {
	if capacity <= 0 {
		capacity = DefaultNonceCapacity
	}
	if ttl <= 0 {
		ttl = DefaultNonceTTL
	}
	return &nonceStore{
		cap:   capacity,
		ttl:   ttl,
		clock: time.Now,
		order: list.New(),
		m:     make(map[string]*list.Element),
	}
}

// increment returns the new nc for nonce, allocating an entry if needed.
func (s *nonceStore) increment(nonce string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.clock()
	s.sweepExpiredLocked(now)

	if el, ok := s.m[nonce]; ok {
		e := el.Value.(*nonceEntry)
		e.nc++
		e.lastSeen = now
		s.order.MoveToFront(el)
		return e.nc
	}

	if s.order.Len() >= s.cap {
		s.evictOldestLocked()
	}
	e := &nonceEntry{nonce: nonce, nc: 1, lastSeen: now}
	s.m[nonce] = s.order.PushFront(e)
	return 1
}

// reset drops the given nonce from the store. Used when a server responds
// stale=true and the nonce is known to be unusable.
func (s *nonceStore) reset(nonce string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if el, ok := s.m[nonce]; ok {
		s.order.Remove(el)
		delete(s.m, nonce)
	}
}

// size reports the number of live entries.
func (s *nonceStore) size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.order.Len()
}

// count returns the current nc for nonce, or 0 if absent. Does not update
// recency.
func (s *nonceStore) count(nonce string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if el, ok := s.m[nonce]; ok {
		return el.Value.(*nonceEntry).nc
	}
	return 0
}

// sweepExpiredLocked evicts entries older than the TTL. Caller must hold mu.
// Walks from the back (oldest) forward and stops at the first non-expired
// entry.
func (s *nonceStore) sweepExpiredLocked(now time.Time) {
	cutoff := now.Add(-s.ttl)
	for {
		back := s.order.Back()
		if back == nil {
			return
		}
		e := back.Value.(*nonceEntry)
		if !e.lastSeen.Before(cutoff) {
			return
		}
		s.order.Remove(back)
		delete(s.m, e.nonce)
	}
}

// evictOldestLocked removes the single least-recently-seen entry. Caller
// must hold mu.
func (s *nonceStore) evictOldestLocked() {
	back := s.order.Back()
	if back == nil {
		return
	}
	e := back.Value.(*nonceEntry)
	s.order.Remove(back)
	delete(s.m, e.nonce)
}
