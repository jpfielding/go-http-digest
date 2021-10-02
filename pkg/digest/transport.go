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
	"io/ioutil"
	"net"
	"net/http"
	"sync"
	"time"
)

// OopPref prefs implemented
type QopPref func([]string) string

// Cnoncer generates a cnonce
type Cnoncer func() string

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
	Cnoncer16 = func() string {
		b := make([]byte, 16)
		io.ReadFull(rand.Reader, b)
		return hex.EncodeToString(b)
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
	// NonCounter tracks the count of all nonces we've sent a request for
	NonceCounter map[string]int
	// QopPref provides a seem for qop selection
	QopPref QopPref
	// Cnoncer provides a seem for cnonce generation
	Cnoncer Cnoncer
	// ncLock mutex's our nonce counter (private and zero init)
	ncLock sync.Mutex
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
		Username:     username,
		Password:     password,
		QopPref:      QopFirst,
		Cnoncer:      Cnoncer16,
		Transport:    transport,
		NonceCounter: map[string]int{}, // consider an lru to keep the size of this in check
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

// Increment tracks the count of the given nonce
func (t *Transport) Increment(nonce string) int {
	t.ncLock.Lock()
	defer t.ncLock.Unlock()
	if _, ok := t.NonceCounter[nonce]; !ok {
		t.NonceCounter[nonce] = 0
	}
	nc := t.NonceCounter[nonce] + 1
	t.NonceCounter[nonce] = nc
	return nc
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
		io.Copy(&body, req.Body)
		req.Body.Close()
		req.Body = ioutil.NopCloser(&body)
	}

	// copy the request so we dont modify the input.
	copy := *req
	copy.Body = ioutil.NopCloser(&body)
	copy.Header = http.Header{}
	for k, s := range req.Header {
		copy.Header[k] = s
	}

	// send the req and see if theres a challenge
	resp, err := t.Transport.RoundTrip(req)
	if err != nil || resp.StatusCode != 401 {
		return resp, err
	}

	// drain and close the connection
	io.Copy(ioutil.Discard, resp.Body)
	resp.Body.Close()

	// accept/reject the challenge
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	chal, err := NewChallenge(wwwAuth)
	if err != nil {
		return resp, err
	}

	// form credentials based on the challenge.
	cr := t.NewCredentials(copy.Method, copy.URL.RequestURI(), body.String(), t.Cnoncer(), chal)
	auth, err := cr.Authorization()
	if err != nil {
		return resp, err
	}

	// make authenticated request.
	copy.Header.Set("Authorization", auth)
	return t.Transport.RoundTrip(&copy)
}
