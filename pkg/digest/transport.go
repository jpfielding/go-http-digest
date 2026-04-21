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
	"time"
)

// OopPref prefs implemented
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

// Transport is an implementation of http.RoundTripper that takes care of http
// digest authentication.
type Transport struct {
	Username  string
	Password  string
	Transport http.RoundTripper

	// NoncePrime is for session keying 'MD5-sess'
	NoncePrime string
	// CnoncePrime is for session keying 'MD5-sess'
	CnoncePrime string
	// QopPref provides a seam for qop selection
	QopPref QopPref
	// Cnoncer provides a seam for cnonce generation
	Cnoncer Cnoncer

	// nonces is a bounded LRU+TTL map tracking the nc value for each nonce.
	// Exposed via Increment / NonceCount / NonceCount.Size.
	nonces *nonceStore
}

// NewHTTPClient returns an HTTP client that uses the digest transport.
func (t *Transport) NewHTTPClient() (*http.Client, error) {
	if t.Transport == nil {
		return nil, ErrNilTransport
	}
	return &http.Client{Transport: t}, nil
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

// NewHTTPTransport ...
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

// NewCredentials ...
func (t *Transport) NewCredentials(method, uri, body, cnonce string, c *Challenge) *Credentials {
	// store these for the life of the transport
	if t.NoncePrime == "" {
		t.NoncePrime = c.Nonce
	}
	if t.CnoncePrime == "" {
		t.CnoncePrime = cnonce
	}
	return &Credentials{
		Username:    t.Username,
		Password:    t.Password,
		Realm:       c.Realm,
		Algorithm:   c.Algorithm,
		Opaque:      c.Opaque,
		Qop:         t.QopPref(c.Qop),
		NoncePrime:  t.NoncePrime,
		CnoncePrime: t.CnoncePrime,
		Nonce:       c.Nonce,
		NonceCount:  t.Increment(c.Nonce),
		Cnonce:      cnonce,
		Method:      method,
		URI:         uri,
		Body:        body,
	}
}

// RoundTrip sends our request and intercepts a 401
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.Transport == nil {
		return nil, ErrNilTransport
	}

	// cache req body (lets hope this isnt big or refactor)
	var body bytes.Buffer
	if req.Body != nil {
		if _, err := io.Copy(&body, req.Body); err != nil {
			return nil, err
		}
		req.Body.Close()
		req.Body = io.NopCloser(&body)
	}

	// copy the request so we don't modify the input.
	copy := req.Clone(req.Context())
	copy.Body = io.NopCloser(bytes.NewBuffer(body.Bytes()))

	// send the req and see if theres a challenge
	resp, err := t.Transport.RoundTrip(req)
	if err != nil || resp.StatusCode != 401 {
		return resp, err
	}

	// drain and close the connection
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return resp, err
	}
	_ = resp.Body.Close()

	// accept/reject the challenge
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if wwwAuth == "" {
		// fall back to non-standard header that some servers use to avoid browser popups
		wwwAuth = resp.Header.Get("X-WWW-Authenticate")
	}
	chal, err := NewChallenge(wwwAuth)
	if err != nil {
		return resp, err
	}

	// form credentials based on the challenge.
	cnonce, err := t.Cnoncer()
	if err != nil {
		return resp, err
	}

	cr := t.NewCredentials(copy.Method, copy.URL.RequestURI(), body.String(), cnonce, chal)
	auth, err := cr.Authorization()
	if err != nil {
		return resp, err
	}

	// make authenticated request.
	copy.Header.Set("Authorization", auth)
	return t.Transport.RoundTrip(copy)
}
