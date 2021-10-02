package main

import (
	"flag"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"

	"github.com/jpfielding/go-http-digest/pkg/digest"

	"github.com/jpfielding/gowirelog/wirelog"
)

type Args struct {
	Username string
	Password string
	URL      string
	Wirelog  string
}

// Parse ...
func (a *Args) Parse() {
	flag.StringVar(&a.Username, "username", "", "the digests username")
	flag.StringVar(&a.Password, "password", "", "digest password")
	flag.StringVar(&a.URL, "url", "", "the url to request")
	flag.StringVar(&a.Wirelog, "wirelog", "", "the log file to see raw http")
	flag.Parse()
}

func main() {
	transport := digest.DefaultHTTPTransport()
	args := &Args{}
	args.Parse()

	// Setup transport to handle digest
	dt := digest.NewTransport(args.Username, args.Password, transport)
	// hook in wirelogging if requested
	if args.Wirelog != "" {
		_, err := wirelog.LogToFile(transport, args.Wirelog, true, false)
		if err != nil {
			panic(err)
		}
	}
	client := &http.Client{
		Transport: dt,
	}
	client.Jar, _ = cookiejar.New(nil)
	resp, err := client.Get(args.URL)
	if err != nil {
		panic(err)
	}
	if _, err := io.Copy(os.Stdout, resp.Body); err == nil {
		_ = resp.Body.Close()
	}
}
