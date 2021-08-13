package digest

import (
	"regexp"
	"strings"
)

// Challenge is the digest response www-authenticate header parsed (rfc 7616)
type Challenge struct {
	Scheme    string
	Realm     string
	Domain    string
	Nonce     string
	Opaque    string
	Stale     string
	Algorithm string
	Qop       []string
	Charset   string
	Userhash  string
}

// the regex will only pull (k="v"|k=v)
var reWwwAuth = regexp.MustCompile(`(\w+\=\".*?\")|(\w+\=[^\,]*)`)

// NewChallenge parses the www-authenticate header
func NewChallenge(wwwAuth string) (*Challenge, error) {
	c := &Challenge{}
	// take everything up to first space (e.g. 'Digest ')
	c.Scheme = strings.SplitN(wwwAuth, " ", 2)[0]
	const qs = `"`
	for _, kv := range reWwwAuth.FindAllString(wwwAuth, -1) {
		parts := strings.SplitN(kv, "=", 2)
		k, v := strings.ToLower(parts[0]), strings.Trim(parts[1], qs)
		switch k {
		case "algorithm":
			c.Algorithm = v
		case "domain":
			c.Domain = v
		case "nonce":
			c.Nonce = v
		case "opaque":
			c.Opaque = v
		case "qop":
			c.Qop = strings.Split(v, ",")
		case "realm":
			c.Realm = v
		case "stale":
			c.Stale = v
		case "charset":
			c.Charset = v
		case "userhash":
			c.Userhash = v
		default:
			return nil, ErrBadChallenge
		}
	}
	return c, nil
}
