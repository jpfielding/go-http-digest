package digest

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
