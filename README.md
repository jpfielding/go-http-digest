# HTTP Digest Authentication

[![GoDoc](https://godoc.org/github.com/jpfielding/go-http-digest?status.svg)](https://godoc.org/github.com/jpfielding/go-http-digest)

An `http.RoundTripper` implementation of RFC 7616 HTTP Digest Authentication.

Supports `MD5`, `SHA-256`, `SHA-512`, `SHA-512-256` and the `-sess` variants of each,
with both `auth` and `auth-int` qop.

## Usage

```go
package main

import (
    "io"
    "log"
    "net/http"
    "net/http/cookiejar"
    "os"

    "github.com/jpfielding/go-http-digest/pkg/digest"
)

func main() {
    dt := digest.NewTransport("user", "pwd", digest.DefaultHTTPTransport())
    client := dt.Client()
    client.Jar, _ = cookiejar.New(nil)

    // SHA-256 is required by some APIs (e.g. MongoDB Atlas for Government).
    resp, err := client.Get("https://cloud.mongodbgov.com/api/atlas/v1.0/groups/<proj>/clusters/<cluster>")
    if err != nil {
        log.Fatal(err)
    }
    defer resp.Body.Close()

    if _, err := io.Copy(os.Stdout, resp.Body); err != nil {
        log.Fatal(err)
    }
}
```
