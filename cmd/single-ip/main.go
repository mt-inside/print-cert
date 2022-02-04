package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	dmp "github.com/sergi/go-diff/diffmatchpatch"

	"bitbucket.mwam.local/infra/lb-checker/pkg/utils"
	. "bitbucket.mwam.local/infra/lb-checker/pkg/utils"
)

func main() {

	if len(os.Args) != 5 {
		fmt.Println("Usage: f5Host nsIP port scheme")
		os.Exit(1)
	}

	f5Host := os.Args[1]
	nsIp := net.ParseIP(os.Args[2])
	port := os.Args[3]
	scheme := os.Args[4]

	if nsIp == nil {
		CheckErr(fmt.Errorf("Invalid IP: %s", os.Args[0]))
	}
	if !(scheme == "http" || scheme == "https") {
		CheckErr(fmt.Errorf("Unknown scheme: %s", scheme))
	}

	fmt.Printf("Testing NetScaler VIP %v against F5 service %v\n", AddrStyle.Render(nsIp.String()), AddrStyle.Render(f5Host))

	/* Check DNS */

	Banner("DNS")

	f5Ip := CheckDns(f5Host)
	f5RevHost := CheckRevDns(f5Ip)
	checkDnsConsistent(f5Host, f5RevHost)

	nsHost := CheckRevDns(nsIp)
	nsRevIp := CheckDns(nsHost)
	checkDnsConsistent(nsIp.String(), nsRevIp.String())

	//do for f5 and ns. For ns, don't rely on the dns so use f5host

	/* Check F5 */

	Banner("Existing F5")

	f5L4Addr := net.JoinHostPort(f5Host, port)
	switch scheme {
	case "http":
		checkTcp(f5L4Addr)
	case "https":
		utils.CheckTls(f5L4Addr, f5Host)
	}

	f5L7Addr := &url.URL{
		Scheme: scheme,
		Host:   f5L4Addr,
		Path:   "/",
	}
	checkHttp(f5L7Addr, f5Host)

	/* Check NetScaler */

	Banner("New NetScaler")

	nsL4Addr := net.JoinHostPort(nsIp.String(), port)
	switch scheme {
	case "http":
		checkTcp(nsL4Addr)
	case "https":
		utils.CheckTls(nsL4Addr, f5Host)
	}

	nsL7Addr := &url.URL{
		Scheme: scheme,
		Host:   nsL4Addr,
		Path:   "/",
	}
	checkHttp(nsL7Addr, f5Host)

	/* Body diff */

	Banner("Differences")

	f5Body := getBody(f5L7Addr, f5Host)
	nsBody := getBody(nsL7Addr, f5Host)

	differ := dmp.New()
	diffs := differ.DiffMain(f5Body, nsBody, true)

	if !(len(diffs) == 1 && diffs[0].Type == dmp.DiffEqual) {
		fmt.Printf("%s response bodies differ\n", SError)
		fmt.Println(differ.DiffPrettyText(diffs))
	} else {
		fmt.Printf("%s response bodies equal\n", SOk)
	}

	/* Fin */

	fmt.Println()
	fmt.Println()

	os.Exit(0)
}

func checkDnsConsistent(orig string, rev string) {
	if rev != orig {
		fmt.Printf("\t%s dns inconsistency: %s != %s\n", SWarning, AddrStyle.Render(orig), AddrStyle.Render(rev))
	}
}

func checkTcp(l4Addr string) {
	var d net.Dialer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	fmt.Printf("%s TCP connection with %s...\n", STrying, AddrStyle.Render(l4Addr))
	conn, err := d.DialContext(ctx, "tcp", l4Addr)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	fmt.Printf("%s established TCP connection with %s\n", OkStyle.Render("Ok:"), AddrStyle.Render(l4Addr))
}

func httpGetSniHost(l7Addr *url.URL, host string) (*http.Response, []byte) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName: host, // SNI
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			fmt.Printf("\t%s Redirected to %s\n", SInfo, AddrStyle.Render(req.URL.String()))
			return nil
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", l7Addr.String(), nil)
	CheckErr(err)
	req.Host = host

	resp, err := client.Do(req)
	CheckErr(err)
	defer resp.Body.Close()

	// Have to read the body before we cancel the request context
	rawBody, err := ioutil.ReadAll(resp.Body)
	CheckErr(err)

	return resp, rawBody
}

func checkHttp(l7Addr *url.URL, host string) {
	fmt.Printf("%s HTTP GET for %s with SNI %s, HTTP host: %s...\n", STrying, AddrStyle.Render(l7Addr.String()), AddrStyle.Render(host), AddrStyle.Render(host))

	resp, _ := httpGetSniHost(l7Addr, host)

	fmt.Printf("%s HTTP GET for %s => %s\n", SOk, AddrStyle.Render(l7Addr.String()), InfoStyle.Render(resp.Status))
	fmt.Printf("\t%s %d bytes of %s from %s\n", SInfo, resp.ContentLength, resp.Header.Get("content-type"), resp.Header.Get("server"))
}

func getBody(l7Addr *url.URL, host string) string {
	_, rawBody := httpGetSniHost(l7Addr, host)

	fmt.Printf("\t%s actual body length %d\n", SInfo, len(rawBody))

	return string(rawBody)
}

/*
   fun as ./script.go

   current:
   * hit it with an http/s GET /
   * show redirects
   * show server and other fun headers
   new:
   * hit new ip (arg) with same tcp, http etc
   * use host header from current dns
   * diff replies

   run me in jenkins as a regression test
*/
