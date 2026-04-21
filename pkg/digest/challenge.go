package digest

import (
	"regexp"
	"strings"
)

// Challenge is the parsed form of a Digest WWW-Authenticate challenge
// (RFC 7616 §3.3).
type Challenge struct {
	Scheme    string
	Realm     string
	Domain    string
	Nonce     string
	Opaque    string
	Stale     string
	Algorithm string
	Qop       []string
	// Charset is informational per RFC 7616 §3.4. The only defined value is
	// "UTF-8"; Go source strings are already UTF-8, so no transcoding is
	// required on the client side.
	Charset string
	// Userhash is "true" when the server has requested that the client hash
	// the username into the Authorization response. See RFC 7616 §3.4.4.
	Userhash string
}

// UserhashRequested reports whether the challenge asked the client to hash
// the username in the Authorization header (RFC 7616 §3.4.4).
func (c *Challenge) UserhashRequested() bool {
	return strings.EqualFold(c.Userhash, "true")
}

// reWwwAuth matches `key="quoted value"` or `key=bareToken` pairs inside a
// WWW-Authenticate header. It does NOT handle backslash-escaped quotes inside
// quoted strings — RFC 7616 allows them, but no known digest server emits
// them in practice, and upgrading to a full RFC 7235 tokenizer is out of
// scope for this change.
var reWwwAuth = regexp.MustCompile(`(\w+=\".*?\")|(\w+=[^,]*)`)

// NewChallenge parses a WWW-Authenticate header value into a Challenge.
//
// Unknown parameters are silently ignored. RFC 7616 §3.3 says clients MUST
// ignore any directives they do not understand, and future RFC extensions
// (or vendor-specific attributes) will include keys this implementation
// doesn't know about. Returning an error here would make the transport
// brittle against server-side evolution.
func NewChallenge(wwwAuth string) (*Challenge, error) {
	c := &Challenge{}
	// Take the scheme token (everything up to the first space).
	c.Scheme = strings.SplitN(wwwAuth, " ", 2)[0]
	const qs = `"`
	for _, kv := range reWwwAuth.FindAllString(wwwAuth, -1) {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		k, v := strings.ToLower(strings.TrimSpace(parts[0])), strings.Trim(parts[1], qs)
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
			// trim whitespace around each listed qop
			qs := strings.Split(v, ",")
			for i := range qs {
				qs[i] = strings.TrimSpace(qs[i])
			}
			c.Qop = qs
		case "realm":
			c.Realm = v
		case "stale":
			c.Stale = v
		case "charset":
			c.Charset = v
		case "userhash":
			c.Userhash = v
		}
	}
	return c, nil
}
