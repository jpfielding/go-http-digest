# HTTP Digest Authentication

[![GoDoc](https://godoc.org/github.com/jpfielding/go-http-digest?status.svg)](https://godoc.org/github.com/jpfielding/go-http-digest)


> Simple digest auth 

``` go
package main

import (
	"net/http"
    	"os"
	"github.com/jpfielding/go-http-digest/pkg/digest"
)

func main() {
    // helper to create the default-ish transport
    transport := digest.DefaultHTTPTransport()
    dt := digest.NewTransport("user", "pwd", transport)
    client := dt.NewHTTPClient()
    client.Jar, _ = cookiejar.New(nil)
    // SHA-256 requrired for mongodbgov.com
    res, _err_ := client.Get("https://cloud.mongodbgov.com/api/atlas/v1.0/groups/<proj>/clusters/<cluster-name>")
    io.Copy(os.Stdout, res.Body)
    if err != nil {
        panic(err)
    }
    defer res.Body.Close()
}
```
