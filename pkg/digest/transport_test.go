package digest

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAlgResponse(t *testing.T) {
	var cnonce = "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ"
	var responses = map[string]string{
		"MD5":     "8ca523f5e9506fed4657c9700eebdbec",
		"SHA-256": "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1",
	}
	for alg, resp := range responses {
		// Digest realm="http-auth@example.org", qop="auth", algorithm=%s, nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"
		challenge := &Challenge{
			Scheme:    "Digest",
			Realm:     "http-auth@example.org",
			Qop:       []string{"auth", "auth-int"},
			Algorithm: alg,
			Nonce:     "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",
			Opaque:    "FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS",
		}

		trans := NewTransport("Mufasa", "Circle of Life", nil)
		// Form credentials based on the challenge.
		cr := trans.NewCredentials("GET", "/dir/index.html", "", cnonce, challenge)
		response, err := cr.response()
		assert.Nil(t, err)
		assert.Equal(t, resp, response)
	}
}
