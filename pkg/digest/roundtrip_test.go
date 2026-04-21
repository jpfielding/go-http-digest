package digest

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// digestServer issues a Digest challenge on the first request and accepts any
// Authorization header on the second. It is NOT a conformant digest server —
// it exists only to exercise the RoundTripper's retry / request-cloning /
// body-replay behavior.
type digestServer struct {
	challenge   string                                           // full WWW-Authenticate header value
	staleOnce   bool                                             // if true, first auth attempt also 401s with stale=true
	staleServed atomic.Bool                                      // tracks whether the stale retry has been issued
	handler     func(r *http.Request, body []byte) (int, []byte) // final handler for authenticated request
	seenAuth    []string                                         // Authorization headers observed, in order
	seenBodies  [][]byte                                         // request bodies observed, in order
}

func (s *digestServer) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	_ = r.Body.Close()
	s.seenBodies = append(s.seenBodies, body)
	auth := r.Header.Get("Authorization")
	s.seenAuth = append(s.seenAuth, auth)

	if auth == "" {
		w.Header().Set("WWW-Authenticate", s.challenge)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if s.staleOnce && !s.staleServed.Swap(true) {
		stale := strings.Replace(s.challenge, `Digest `, `Digest stale=true, `, 1)
		// rotate nonce on the stale challenge so NC resets are meaningful
		stale = strings.Replace(stale, `nonce="n1"`, `nonce="n2"`, 1)
		w.Header().Set("WWW-Authenticate", stale)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if s.handler != nil {
		status, respBody := s.handler(r, body)
		w.WriteHeader(status)
		_, _ = w.Write(respBody)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func newTestServer(t *testing.T, s *digestServer) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(s.serve))
}

// TestRoundTripDoesNotMutateRequest captures the incoming *http.Request before
// RoundTrip runs and asserts its Body is still readable with the original
// contents and the Header is untouched afterwards. This guards against the
// previous behavior where RoundTrip drained and replaced req.Body in place.
func TestRoundTripDoesNotMutateRequest(t *testing.T) {
	const payload = "hello-world-payload"
	srv := &digestServer{challenge: `Digest realm="r", qop="auth", algorithm=MD5, nonce="n1"`}
	ts := newTestServer(t, srv)
	defer ts.Close()

	trans := NewTransport("u", "p", http.DefaultTransport)

	req, err := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(payload))
	require.NoError(t, err)
	req.Header.Set("X-Custom", "keep-me")

	resp, err := trans.RoundTrip(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "keep-me", req.Header.Get("X-Custom"))
	assert.Empty(t, req.Header.Get("Authorization"),
		"Authorization must not leak onto the caller's req")

	// The caller's body must still be readable in full: http.NewRequest
	// populates GetBody for strings.Reader, and RoundTrip must source from
	// GetBody rather than drain req.Body in place.
	remaining, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.Equal(t, payload, string(remaining),
		"original req.Body must still yield the full payload after RoundTrip")

	// And the server saw the body on both attempts.
	require.Len(t, srv.seenBodies, 2)
	assert.Equal(t, payload, string(srv.seenBodies[0]))
	assert.Equal(t, payload, string(srv.seenBodies[1]))
}

// TestRoundTripStaleRetry verifies that a 401 with stale=true on the
// authenticated attempt triggers a single retry with the new nonce.
func TestRoundTripStaleRetry(t *testing.T) {
	srv := &digestServer{
		challenge: `Digest realm="r", qop="auth", algorithm=MD5, nonce="n1"`,
		staleOnce: true,
	}
	ts := newTestServer(t, srv)
	defer ts.Close()

	trans := NewTransport("u", "p", http.DefaultTransport)
	resp, err := trans.RoundTrip(mustGet(t, ts.URL))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	// 3 requests total: unauth, first auth (stale), retry with new nonce.
	assert.Len(t, srv.seenAuth, 3)
	assert.Empty(t, srv.seenAuth[0])
	assert.Contains(t, srv.seenAuth[1], `nonce="n1"`)
	assert.Contains(t, srv.seenAuth[2], `nonce="n2"`)
}

// TestRoundTripAuthIntBodyHash ensures the request body is available for the
// auth-int qop hash on a non-trivial body.
func TestRoundTripAuthIntBodyHash(t *testing.T) {
	srv := &digestServer{
		challenge: `Digest realm="r", qop="auth-int", algorithm=MD5, nonce="n1"`,
	}
	ts := newTestServer(t, srv)
	defer ts.Close()

	payload := []byte("POST-body-for-auth-int")
	trans := NewTransport("u", "p", http.DefaultTransport)
	req, err := http.NewRequest(http.MethodPost, ts.URL, bytes.NewReader(payload))
	require.NoError(t, err)

	resp, err := trans.RoundTrip(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	require.Len(t, srv.seenAuth, 2)
	assert.Contains(t, srv.seenAuth[1], `qop=auth-int`)
	// Body was replayed on the authenticated attempt.
	assert.Equal(t, payload, srv.seenBodies[1])
}

// TestRoundTripNonReplayableBody asserts that a body without GetBody support
// still works because the transport falls back to one-time buffering.
func TestRoundTripNonReplayableBody(t *testing.T) {
	srv := &digestServer{challenge: `Digest realm="r", qop="auth", algorithm=MD5, nonce="n1"`}
	ts := newTestServer(t, srv)
	defer ts.Close()

	trans := NewTransport("u", "p", http.DefaultTransport)
	// An *http.Request built via low-level construction with a plain io.Reader
	// that is NOT one of the stdlib types that populates GetBody.
	req, err := http.NewRequest(http.MethodPost, ts.URL, nil)
	require.NoError(t, err)
	req.Body = io.NopCloser(strings.NewReader("once"))
	req.GetBody = nil

	resp, err := trans.RoundTrip(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	require.Len(t, srv.seenBodies, 2)
	assert.Equal(t, "once", string(srv.seenBodies[0]))
	assert.Equal(t, "once", string(srv.seenBodies[1]))
}

func mustGet(t *testing.T, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	require.NoError(t, err)
	return req
}

// TestRoundTripNoDigestChallenge covers issue #6: when a 401 response carries
// no WWW-Authenticate header (or only non-Digest schemes), the transport must
// return the 401 to the caller as-is instead of emitting a second request
// with empty/garbage digest credentials.
func TestRoundTripNoDigestChallenge(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{
			name: "no WWW-Authenticate header at all",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
			},
		},
		{
			name: "only Basic scheme offered",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("WWW-Authenticate", `Basic realm="secure"`)
				w.WriteHeader(http.StatusUnauthorized)
			},
		},
		{
			name: "only Bearer scheme offered",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("WWW-Authenticate", `Bearer realm="api"`)
				w.WriteHeader(http.StatusUnauthorized)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var requests int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&requests, 1)
				// Guard: if the client attempts a second request it MUST NOT
				// carry an Authorization header — if it does, the bug is live.
				if r.Header.Get("Authorization") != "" {
					t.Errorf("unexpected second request with Authorization=%q", r.Header.Get("Authorization"))
				}
				tc.handler(w, r)
			}))
			defer srv.Close()

			trans := NewTransport("u", "p", http.DefaultTransport)
			resp, err := trans.RoundTrip(mustGet(t, srv.URL))
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
				"caller must see the original 401")
			assert.Equal(t, int32(1), atomic.LoadInt32(&requests),
				"transport must not issue a second request when there is no Digest challenge")
		})
	}
}

// TestRoundTripMultiSchemeChallenge covers the case where the server lists
// multiple challenges in one WWW-Authenticate header (RFC 7235 §4.1). If any
// of the offered schemes is Digest, we should still authenticate.
func TestRoundTripMultiSchemeChallenge(t *testing.T) {
	srv := &digestServer{
		challenge: `Basic realm="other", Digest realm="r", qop="auth", algorithm=MD5, nonce="n1"`,
	}
	ts := newTestServer(t, srv)
	defer ts.Close()

	trans := NewTransport("u", "p", http.DefaultTransport)
	resp, err := trans.RoundTrip(mustGet(t, ts.URL))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	require.Len(t, srv.seenAuth, 2)
	assert.Contains(t, srv.seenAuth[1], "Digest ")
}

func TestHasDigestScheme(t *testing.T) {
	cases := []struct {
		header string
		want   bool
	}{
		{"", false},
		{`Basic realm="x"`, false},
		{`Bearer realm="api"`, false},
		{`Digest realm="r", nonce="n"`, true},
		{`digest realm="r"`, true}, // case-insensitive
		{`DIGEST realm="r"`, true}, // all-caps
		{`Basic realm="x", Digest realm="y"`, true},
		{`NTLM`, false},
		{`Digests realm="r"`, false}, // not the scheme token
		{`XDigest`, false},           // not preceded by start/comma
	}
	for _, tc := range cases {
		h := http.Header{}
		if tc.header != "" {
			h.Set("WWW-Authenticate", tc.header)
		}
		assert.Equal(t, tc.want, hasDigestScheme(h), "header=%q", tc.header)
	}
}
