package digest

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// QopPref prefs implemented
type QopPref func([]string) string

// Cnoncer generates a cnonce
type Cnoncer func() (string, error)

var (
	ErrNilTransport      = errors.New("transport is nil")
	ErrBadChallenge      = errors.New("challenge is bad")
	ErrAlgNotImplemented = errors.New("alg not implemented")
	ErrQopNotSupported   = errors.New("qop not supported")

	// The Algs supported by this digester
	Algs = map[string]func() hash.Hash{
		"":            md5.New,
		"MD5":         md5.New,
		"SHA-256":     sha256.New,
		"SHA-512":     sha512.New,
		"SHA-512-256": sha512.New512_256,
	}
	QopFirst = func(qops []string) string {
		for _, qop := range qops {
			return qop
		}
		return ""
	}
	Cnoncer16 = func() (string, error) {
		b := make([]byte, 16)
		_, err := io.ReadFull(rand.Reader, b)
		return hex.EncodeToString(b), err
	}
)

// maxAuthAttempts bounds the authenticated retries after the initial 401.
// One attempt for the normal challenge/response round, plus one more if the
// server returns 401 with stale=true.
const maxAuthAttempts = 2

// Transport is an implementation of http.RoundTripper that takes care of http
// digest authentication.
type Transport struct {
	Username  string
	Password  string
	Transport http.RoundTripper

	// QopPref provides a seam for qop selection.
	QopPref QopPref
	// Cnoncer provides a seam for cnonce generation.
	Cnoncer Cnoncer

	// nonces is a bounded LRU+TTL map tracking the nc value for each nonce.
	// Exposed via Increment / NonceCount / TrackedNonces.
	nonces *nonceStore
}

// Client returns an *http.Client that uses this Transport as its RoundTripper.
// Callers typically attach a cookie jar, set a Timeout, etc. on the returned
// client before use.
func (t *Transport) Client() *http.Client {
	return &http.Client{Transport: t}
}

// NewTransport creates a new digest transport using the http.DefaultTransport.
func NewTransport(username, password string, transport http.RoundTripper) *Transport {
	if transport == nil {
		transport = DefaultHTTPTransport()
	}
	return &Transport{
		Username:  username,
		Password:  password,
		QopPref:   QopFirst,
		Cnoncer:   Cnoncer16,
		Transport: transport,
		nonces:    newNonceStore(DefaultNonceCapacity, DefaultNonceTTL),
	}
}

// DefaultHTTPTransport returns an *http.Transport pre-configured with the
// stdlib defaults. It is a convenience for callers who want a transport they
// can modify (e.g. custom TLS, proxy) before handing it to NewTransport.
func DefaultHTTPTransport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// Increment bumps and returns the nc for the given nonce.
func (t *Transport) Increment(nonce string) int {
	if t.nonces == nil {
		t.nonces = newNonceStore(DefaultNonceCapacity, DefaultNonceTTL)
	}
	return t.nonces.increment(nonce)
}

// NonceCount returns the current nc for the given nonce, or 0 if the nonce
// is not tracked. Does not update recency.
func (t *Transport) NonceCount(nonce string) int {
	if t.nonces == nil {
		return 0
	}
	return t.nonces.count(nonce)
}

// TrackedNonces reports the number of nonces currently in the counter.
func (t *Transport) TrackedNonces() int {
	if t.nonces == nil {
		return 0
	}
	return t.nonces.size()
}

// resetNonce removes the given nonce from the counter so the next Increment
// starts at 1. Used when a server responds stale=true.
func (t *Transport) resetNonce(nonce string) {
	if t.nonces == nil {
		return
	}
	t.nonces.reset(nonce)
}

// NewCredentials constructs the per-request Credentials for a given challenge.
// For -sess algorithms, the nonce and cnonce of THIS challenge are used as
// the sess inputs (nonce-prime, cnonce-prime). RFC 7616 §3.4.4 allows any
// previous nonce/cnonce pair; using the current pair keeps each challenge
// self-contained and avoids cross-server contamination.
func (t *Transport) NewCredentials(method, uri string, body []byte, cnonce string, c *Challenge) *Credentials {
	return &Credentials{
		Username:    t.Username,
		Password:    t.Password,
		Realm:       c.Realm,
		Algorithm:   c.Algorithm,
		Opaque:      c.Opaque,
		Qop:         t.QopPref(c.Qop),
		Userhash:    c.UserhashRequested(),
		NoncePrime:  c.Nonce,
		CnoncePrime: cnonce,
		Nonce:       c.Nonce,
		NonceCount:  t.Increment(c.Nonce),
		Cnonce:      cnonce,
		Method:      method,
		URI:         uri,
		Body:        string(body),
	}
}

// readChallenge pulls the digest challenge from either the standard header or
// the non-standard X-WWW-Authenticate that some servers use to avoid browser
// auth popups.
func readChallenge(h http.Header) (*Challenge, error) {
	wwwAuth := h.Get("WWW-Authenticate")
	if wwwAuth == "" {
		wwwAuth = h.Get("X-WWW-Authenticate")
	}
	return NewChallenge(wwwAuth)
}

// digestSchemeRE matches the "Digest" auth-scheme token when it appears at
// the start of a challenge list or after a comma separator (RFC 7235 allows
// multiple challenges in one header, e.g. `Basic realm="x", Digest realm="y"`).
var digestSchemeRE = regexp.MustCompile(`(?i)(?:^|,)\s*Digest(?:\s|$)`)

// hasDigestScheme reports whether any WWW-Authenticate (or X-WWW-Authenticate
// fallback) header value actually advertises the Digest scheme. Servers that
// return 401 without a WWW-Authenticate header at all, or that offer only
// non-Digest schemes (Basic, Bearer, NTLM), leave nothing for this transport
// to answer.
func hasDigestScheme(h http.Header) bool {
	values := h.Values("WWW-Authenticate")
	if len(values) == 0 {
		values = h.Values("X-WWW-Authenticate")
	}
	for _, v := range values {
		if digestSchemeRE.MatchString(v) {
			return true
		}
	}
	return false
}

// RoundTrip implements http.RoundTripper. It issues the request; on a 401 it
// parses the challenge, constructs digest credentials, and retries with an
// Authorization header. Retries once more if the server returns stale=true.
//
// The caller's *http.Request and its Body are NEVER mutated. Each attempt
// uses a clone of the request with a freshly-sourced body. For requests with
// a non-nil Body, bodies are sourced from req.GetBody when provided; otherwise
// the body is buffered once on entry so it can be replayed on the retry.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.Transport == nil {
		return nil, ErrNilTransport
	}

	// Source bodies for each attempt without mutating req.
	bodySrc, err := newBodySource(req)
	if err != nil {
		return nil, err
	}

	attempt := func(authHeader string) (*http.Response, []byte, error) {
		clone := req.Clone(req.Context())
		bodyRC, bodyBytes, err := bodySrc.next()
		if err != nil {
			return nil, nil, err
		}
		if bodyRC != nil {
			clone.Body = bodyRC
			clone.ContentLength = int64(len(bodyBytes))
		}
		if authHeader != "" {
			// Clone defensively; req.Clone already shallow-copies headers
			// but Set on a shared slice would still be unsafe under some
			// stdlib internals paths.
			clone.Header = clone.Header.Clone()
			clone.Header.Set("Authorization", authHeader)
		}
		resp, err := t.Transport.RoundTrip(clone)
		return resp, bodyBytes, err
	}

	// Initial unauthenticated request.
	resp, bodyBytes, err := attempt("")
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}

	// A 401 without a Digest challenge is not ours to answer. Return the
	// response to the caller unchanged rather than emitting a second
	// request with empty/garbage credentials (fixes #6).
	if !hasDigestScheme(resp.Header) {
		return resp, nil
	}

	// Authenticated attempts (initial + optional stale retry).
	for i := 0; i < maxAuthAttempts; i++ {
		if _, e := io.Copy(io.Discard, resp.Body); e != nil {
			return resp, e
		}
		_ = resp.Body.Close()

		chal, err := readChallenge(resp.Header)
		if err != nil {
			return resp, err
		}

		cnonce, err := t.Cnoncer()
		if err != nil {
			return resp, err
		}

		cr := t.NewCredentials(req.Method, req.URL.RequestURI(), bodyBytes, cnonce, chal)
		authHeader, err := cr.Authorization()
		if err != nil {
			return resp, err
		}

		resp, bodyBytes, err = attempt(authHeader)
		if err != nil {
			return resp, err
		}
		if resp.StatusCode != http.StatusUnauthorized {
			return resp, nil
		}

		// 401 again — retry only if the server explicitly says stale=true.
		nextChal, err := readChallenge(resp.Header)
		if err != nil || !strings.EqualFold(nextChal.Stale, "true") {
			return resp, nil
		}
		// The old nonce is burned; evict it so the next attempt starts at
		// nc=1 for whatever new nonce arrives.
		t.resetNonce(chal.Nonce)
	}

	return resp, nil
}

// bodySource produces fresh io.ReadCloser + raw byte views of a request body
// for each attempt, without mutating the caller's *http.Request.
type bodySource struct {
	req      *http.Request
	buffered []byte // used when req.GetBody is nil
	hasBody  bool
}

func newBodySource(req *http.Request) (*bodySource, error) {
	bs := &bodySource{req: req}
	if req.Body == nil || req.Body == http.NoBody {
		return bs, nil
	}
	bs.hasBody = true
	if req.GetBody != nil {
		// No buffering needed; GetBody re-creates the reader on demand.
		return bs, nil
	}
	// Fall back to a one-time buffer of the original body. This is the only
	// case where we read from req.Body — but we do NOT replace req.Body or
	// close it in-place, so the caller's request object is left alone.
	b, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	_ = req.Body.Close()
	bs.buffered = b
	return bs, nil
}

// next returns a fresh ReadCloser and the underlying bytes (for auth-int
// hashing). Returns (nil, nil, nil) when the request has no body.
func (b *bodySource) next() (io.ReadCloser, []byte, error) {
	if !b.hasBody {
		return nil, nil, nil
	}
	if b.req.GetBody != nil {
		rc, err := b.req.GetBody()
		if err != nil {
			return nil, nil, err
		}
		raw, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			return nil, nil, err
		}
		return io.NopCloser(bytes.NewReader(raw)), raw, nil
	}
	return io.NopCloser(bytes.NewReader(b.buffered)), b.buffered, nil
}
