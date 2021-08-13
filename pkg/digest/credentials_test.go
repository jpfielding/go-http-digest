// https://datatracker.ietf.org/doc/html/rfc7616
package digest

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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
