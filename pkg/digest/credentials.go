package digest

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Credentials holds the per request response params
type Credentials struct {
	// our creds
	Username string
	Password string

	// from the challenge
	Realm      string
	Nonce      string
	NonceCount int // times we've responded to this nonce
	Opaque     string
	Qop        string // the chosen auth from the server list
	Algorithm  string // <alg>-sess implies session-keying ()
	// Userhash mirrors the challenge's userhash=true flag. When set, the
	// Authorization header emits username=H(unq(username):unq(realm)) and
	// userhash=true instead of the cleartext username (RFC 7616 §3.4.4).
	Userhash bool

	// session-keying
	CnoncePrime string
	NoncePrime  string

	// per response
	Method string
	URI    string
	Body   string // used for auth-int
	Cnonce string
}

type Hasher func(string) string

// baseAlg returns the algorithm name with any "-sess" suffix stripped
// and the scheme uppercased, matching the keys in the Algs map.
func (c *Credentials) baseAlg() string {
	return strings.TrimSuffix(strings.ToUpper(c.Algorithm), "-SESS")
}

// isSess reports whether the algorithm uses session-keyed HA1 per
// RFC 7616 §3.4.2.
func (c *Credentials) isSess() bool {
	return strings.HasSuffix(strings.ToUpper(c.Algorithm), "-SESS")
}

func (c *Credentials) Hasher() Hasher {
	alg := c.baseAlg()
	return func(data string) string {
		h := Algs[alg]() // create the hash.Hash to avoid sharing
		h.Reset()
		fmt.Fprint(h, data)
		return hex.EncodeToString(h.Sum(nil))
	}
}

func (c *Credentials) kd(secret, data string) string {
	return fmt.Sprintf("%s:%s", secret, data)
}

// ha1 computes the HA1 value per RFC 7616 §3.4.2.
//
//	HA1       = H( unq(username) ":" unq(realm) ":" passwd )
//	HA1-sess  = H( H(unq(username) ":" unq(realm) ":" passwd)
//	               ":" unq(nonce-prime) ":" unq(cnonce-prime) )
//
// The -sess form is a nested hash: H(H(...):nonce-prime:cnonce-prime).
func (c *Credentials) ha1() string {
	h := c.Hasher()
	base := h(strings.Join([]string{c.Username, c.Realm, c.Password}, ":"))
	if c.isSess() {
		return h(strings.Join([]string{base, c.NoncePrime, c.CnoncePrime}, ":"))
	}
	return base
}

func (c *Credentials) a2() string {
	var a2 []string
	a2 = append(a2, c.Method)
	a2 = append(a2, c.URI)
	if strings.HasSuffix(c.Qop, "-int") {
		h := c.Hasher()
		a2 = append(a2, h(c.Body))
	}
	return strings.Join(a2, ":")
}

func (c *Credentials) response() (string, error) {
	h := c.Hasher()
	ha1 := c.ha1()
	ha2 := h(c.a2())
	switch c.Qop {
	case "auth", "auth-int":
		var data []string
		data = append(data, c.Nonce)
		data = append(data, fmt.Sprintf("%08x", c.NonceCount))
		data = append(data, c.Cnonce)
		data = append(data, c.Qop)
		data = append(data, ha2)
		return h(c.kd(ha1, strings.Join(data, ":"))), nil
	case "": // compat with rfc2617
		var data []string
		data = append(data, c.Nonce)
		data = append(data, ha2)
		return h(c.kd(ha1, strings.Join(data, ":"))), nil
	default:
		return "", ErrQopNotSupported
	}
}

func (c *Credentials) Authorization() (string, error) {
	if _, ok := Algs[c.baseAlg()]; !ok {
		return "", ErrAlgNotImplemented
	}
	resp, err := c.response()
	if err != nil {
		return "", err
	}
	var auth []string
	username := c.Username
	if c.Userhash {
		h := c.Hasher()
		username = h(c.Username + ":" + c.Realm)
	}
	auth = append(auth, fmt.Sprintf(`username="%s"`, username))
	auth = append(auth, fmt.Sprintf(`realm="%s"`, c.Realm))
	auth = append(auth, fmt.Sprintf(`nonce="%s"`, c.Nonce))
	auth = append(auth, fmt.Sprintf(`uri="%s"`, c.URI))
	if c.Opaque != "" {
		auth = append(auth, fmt.Sprintf(`opaque="%s"`, c.Opaque))
	}
	if c.Qop != "" {
		auth = append(auth, fmt.Sprintf(`cnonce="%s"`, c.Cnonce))
		auth = append(auth, fmt.Sprintf("nc=%08x", c.NonceCount))
		auth = append(auth, fmt.Sprintf("qop=%s", c.Qop))
	}
	auth = append(auth, fmt.Sprintf(`response="%s"`, resp))
	if c.Algorithm != "" {
		auth = append(auth, fmt.Sprintf(`algorithm=%s`, c.Algorithm))
	}
	if c.Userhash {
		auth = append(auth, `userhash=true`)
	}
	return fmt.Sprintf("Digest %s", strings.Join(auth, ", ")), nil
}
