package main

import (
	"fmt"
	"net"

	. "bitbucket.mwam.local/infra/lb-checker/pkg/utils"
)

var (
	dnsNames = []string{
		"p-eu-elasticsearch",
		"p-eu-logstash",
	}

	f5Ips = []string{
		"10.10.74.243",
		"10.100.100.203",
	}

	nsIps = []string{
		"10.11.7.113",
	}
)

func main() {
	dnsIps := map[string]struct{}{}

	for _, name := range dnsNames {
		ips, err := net.LookupHost(name)
		CheckErr(err)
		for _, ip := range ips {
			if _, found := dnsIps[ip]; found {
				CheckErr(fmt.Errorf("Two names point to same IP; second name is %s", name))
			}
			dnsIps[ip] = struct{}{}
		}
	}

	f5Names := map[string]struct{}{}

	for _, ip := range f5Ips {
		names, err := net.LookupAddr(ip)
		CheckErr(err)
		for _, name := range names {
			if _, found := f5Names[name]; found {
				CheckErr(fmt.Errorf("Two F5 IPs reverse to the same name; second IP is %s", ip))
			}
			f5Names[ip] = struct{}{}
		}
	}

	fmt.Println("Given names point to IPs:")
	for ip, _ := range dnsIps {
		fmt.Printf("  %s\n", AddrStyle.Render(ip))
	}

	fmt.Println("Given F5 IPs reverse to:")
	for ip, _ := range f5Names {
		fmt.Printf("  %s\n", AddrStyle.Render(ip))
	}
}
