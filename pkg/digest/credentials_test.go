package digest

import (
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// examples/responses taken directly from
// https://datatracker.ietf.org/doc/html/rfc7616

func TestResponse(t *testing.T) {
	var responses = map[string]string{
		"MD5":     "8ca523f5e9506fed4657c9700eebdbec",
		"SHA-256": "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1",
	}
	for alg, resp := range responses {
		creds := Credentials{
			Username:   "Mufasa",
			Password:   "Circle of Life",
			Realm:      "http-auth@example.org",
			Algorithm:  alg,
			Opaque:     "FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS",
			Qop:        "auth",
			Nonce:      "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",
			NoncePrime: "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",
			NonceCount: 1,
			Cnonce:     "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ",
			Method:     "GET",
			URI:        "/dir/index.html",
		}
		response, err := creds.response()
		assert.Nil(t, err)
		assert.Equal(t, resp, response)
	}
}

// TestSessHA1Formula verifies that HA1 for -sess variants is computed as
// the nested hash defined in RFC 7616 §3.4.2:
//
//	HA1 = H( H(username:realm:password) : nonce-prime : cnonce-prime )
//
// The previous implementation flattened this into a single hash.
func TestSessHA1Formula(t *testing.T) {
	const (
		user  = "Mufasa"
		pass  = "Circle of Life"
		realm = "http-auth@example.org"
		np    = "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v"
		cp    = "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ"
	)

	cases := []struct {
		alg    string
		hashFn func([]byte) string
	}{
		{"MD5-sess", func(b []byte) string { s := md5.Sum(b); return fmt.Sprintf("%x", s) }},
		{"SHA-256-sess", func(b []byte) string { s := sha256.Sum256(b); return fmt.Sprintf("%x", s) }},
	}

	for _, tc := range cases {
		base := tc.hashFn([]byte(user + ":" + realm + ":" + pass))
		want := tc.hashFn([]byte(base + ":" + np + ":" + cp))

		creds := &Credentials{
			Username:    user,
			Password:    pass,
			Realm:       realm,
			Algorithm:   tc.alg,
			NoncePrime:  np,
			CnoncePrime: cp,
		}
		assert.Equal(t, want, creds.ha1(), "alg=%s", tc.alg)
	}
}

// TestAuthorizationAcceptsSessAlgs guards against the previous bug where
// Algs lookup used the raw algorithm token, causing MD5-sess / SHA-256-sess
// to be rejected with ErrAlgNotImplemented.
func TestAuthorizationAcceptsSessAlgs(t *testing.T) {
	for _, alg := range []string{"MD5-sess", "SHA-256-sess", "SHA-512-256-sess"} {
		creds := &Credentials{
			Username:    "Mufasa",
			Password:    "Circle of Life",
			Realm:       "http-auth@example.org",
			Algorithm:   alg,
			Qop:         "auth",
			Nonce:       "n",
			NoncePrime:  "n",
			NonceCount:  1,
			Cnonce:      "c",
			CnoncePrime: "c",
			Method:      "GET",
			URI:         "/",
		}
		_, err := creds.Authorization()
		assert.Nil(t, err, "alg=%s", alg)
	}
}

// TestBaseAlgCaseInsensitive ensures -sess suffix stripping is case-insensitive.
func TestBaseAlgCaseInsensitive(t *testing.T) {
	cases := map[string]string{
		"MD5-sess":     "MD5",
		"md5-sess":     "MD5",
		"MD5-SESS":     "MD5",
		"SHA-256-sess": "SHA-256",
		"SHA-256":      "SHA-256",
		"":             "",
	}
	for in, want := range cases {
		got := (&Credentials{Algorithm: in}).baseAlg()
		assert.Equal(t, want, got, "alg=%q", in)
	}
}

// TestAuthorizationUserhash verifies that when Userhash is set, the emitted
// username directive carries H(user:realm) and userhash=true is appended,
// per RFC 7616 §3.4.4.
func TestAuthorizationUserhash(t *testing.T) {
	creds := Credentials{
		Username:   "Mufasa",
		Password:   "Circle of Life",
		Realm:      "http-auth@example.org",
		Algorithm:  "SHA-256",
		Nonce:      "n",
		NonceCount: 1,
		Cnonce:     "c",
		Qop:        "auth",
		Method:     "GET",
		URI:        "/",
		Userhash:   true,
	}
	auth, err := creds.Authorization()
	assert.Nil(t, err)
	assert.NotContains(t, auth, `username="Mufasa"`,
		"cleartext username must not appear when userhash is set")
	assert.Contains(t, auth, `userhash=true`,
		"userhash=true must be advertised in the Authorization header")
	// The emitted username value should be the 64-char SHA-256 hex of
	// "Mufasa:http-auth@example.org".
	assert.Regexp(t, `username="[0-9a-f]{64}"`, auth)

	// And without Userhash, the cleartext form should still be used.
	creds.Userhash = false
	auth2, err := creds.Authorization()
	assert.Nil(t, err)
	assert.Contains(t, auth2, `username="Mufasa"`)
	assert.False(t, strings.Contains(auth2, `userhash=true`))
}
