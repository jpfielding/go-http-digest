# HTTP Digest Authentication

> Simple digest auth 

``` go
package main

import (
	"net/http"
    	"os"
	"github.com/jpfielding/go-http-digest/pkg/digest"
)

func main() {
    transport := digest.NewHTTPTransport()
    dt := digest.NewTransport("user", "pwd", transport)
    client := dt.NewHTTPClient()
    client.Jar, _ = cookiejar.New(nil)
    res, _err_ := client.Get("https://cloud.mongodbgov.com/api/atlas/v1.0/groups/<proj>/clusters/<cluster-name>")
    io.Copy(os.Stdout, res.Body)
    defer res.Body.Close()
}
```
