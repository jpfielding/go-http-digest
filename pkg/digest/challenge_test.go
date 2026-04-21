package digest

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var rawChallenge = `Digest realm="http-auth@example.org", qop="auth,auth-int", algorithm=SHA-256, nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"`

func TestParse(t *testing.T) {
	c, err := NewChallenge(rawChallenge)
	assert.Nil(t, err)
	assert.Equal(t, "Digest", c.Scheme)
	assert.Equal(t, "http-auth@example.org", c.Realm)
	assert.Equal(t, "", c.Stale)
	assert.Equal(t, "SHA-256", c.Algorithm)
	assert.Equal(t, "FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS", c.Opaque)
	assert.Equal(t, "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", c.Nonce)
	assert.Equal(t, "auth-int", c.Qop[1])
}

// TestParseIgnoresUnknownKeys guards against the previous behavior where any
// unrecognized parameter caused NewChallenge to return ErrBadChallenge. RFC
// 7616 §3.3 requires clients to ignore unknown directives.
func TestParseIgnoresUnknownKeys(t *testing.T) {
	raw := `Digest realm="r", nonce="n", algorithm=MD5, vendor-ext="ignored", future_flag=1`
	c, err := NewChallenge(raw)
	require.NoError(t, err)
	assert.Equal(t, "r", c.Realm)
	assert.Equal(t, "n", c.Nonce)
	assert.Equal(t, "MD5", c.Algorithm)
}

// TestParseStaleAndUserhash confirms the two RFC 7616 flags are surfaced.
func TestParseStaleAndUserhash(t *testing.T) {
	raw := `Digest realm="r", nonce="n", algorithm=SHA-256, stale=true, userhash=true, charset=UTF-8`
	c, err := NewChallenge(raw)
	require.NoError(t, err)
	assert.Equal(t, "true", c.Stale)
	assert.Equal(t, "true", c.Userhash)
	assert.Equal(t, "UTF-8", c.Charset)
	assert.True(t, c.UserhashRequested())
}

// TestParseQopTrimsWhitespace verifies comma-separated qop lists with
// surrounding whitespace don't leak spaces into Qop entries.
func TestParseQopTrimsWhitespace(t *testing.T) {
	raw := `Digest realm="r", nonce="n", qop="auth, auth-int"`
	c, err := NewChallenge(raw)
	require.NoError(t, err)
	assert.Equal(t, []string{"auth", "auth-int"}, c.Qop)
}
