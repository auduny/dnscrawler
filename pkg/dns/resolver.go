package dns

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type Resolver struct {
	client *dns.Client
}

type TraceStep struct {
	Zone   string
	Server string
}

type Nameserver struct {
	Name string
	IP   string
}

type Records struct {
	A     []string
	AAAA  []string
	MX    []string
	TXT   []string
	NS    []string
	CNAME []string
}

func NewResolver() *Resolver {
	return &Resolver{
		client: &dns.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Exists checks if a domain exists by querying DNS and checking for NXDOMAIN
func (r *Resolver) Exists(domain string) bool {
	domain = dns.Fqdn(domain)
	m := new(dns.Msg)
	m.SetQuestion(domain, dns.TypeNS)
	m.RecursionDesired = true

	resp, _, err := r.client.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return true // assume exists on network error
	}
	return resp.Rcode != dns.RcodeNameError
}

// GetNameservers returns the authoritative nameservers for a domain
func (r *Resolver) GetNameservers(domain string) ([]Nameserver, error) {
	domain = dns.Fqdn(domain)

	m := new(dns.Msg)
	m.SetQuestion(domain, dns.TypeNS)
	m.RecursionDesired = true

	resp, _, err := r.client.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return nil, err
	}

	var nameservers []Nameserver
	for _, ans := range resp.Answer {
		if ns, ok := ans.(*dns.NS); ok {
			nsName := strings.TrimSuffix(ns.Ns, ".")
			ip := r.resolveNS(ns.Ns)
			nameservers = append(nameservers, Nameserver{Name: nsName, IP: ip})
		}
	}

	return nameservers, nil
}

func (r *Resolver) resolveNS(nsName string) string {
	m := new(dns.Msg)
	m.SetQuestion(nsName, dns.TypeA)
	m.RecursionDesired = true

	resp, _, err := r.client.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return ""
	}

	for _, ans := range resp.Answer {
		if a, ok := ans.(*dns.A); ok {
			return a.A.String()
		}
	}
	return ""
}

// Trace performs a DNS trace from root servers
func (r *Resolver) Trace(domain string) ([]TraceStep, error) {
	domain = dns.Fqdn(domain)
	var steps []TraceStep

	// Root servers
	rootServers := []string{
		"198.41.0.4",   // a.root-servers.net
		"199.9.14.201", // b.root-servers.net
		"192.33.4.12",  // c.root-servers.net
	}

	currentServer := rootServers[0]

	// Get domain parts for iteration
	parts := strings.Split(strings.TrimSuffix(domain, "."), ".")
	zones := []string{"."}
	for i := len(parts) - 1; i >= 0; i-- {
		zone := strings.Join(parts[i:], ".") + "."
		zones = append(zones, zone)
	}

	for i, zone := range zones {
		if i == 0 {
			// Root zone
			serverName := r.getRootServerName(currentServer)
			steps = append(steps, TraceStep{Zone: ".", Server: serverName})
			continue
		}

		// Query for NS records of this zone
		m := new(dns.Msg)
		m.SetQuestion(zone, dns.TypeNS)
		m.RecursionDesired = false

		resp, _, err := r.client.Exchange(m, currentServer+":53")
		if err != nil {
			continue
		}

		// Look for NS in authority or answer section
		var nsRecords []dns.RR
		if len(resp.Answer) > 0 {
			nsRecords = resp.Answer
		} else if len(resp.Ns) > 0 {
			nsRecords = resp.Ns
		}

		var nextServer string
		var serverName string

		for _, rr := range nsRecords {
			if ns, ok := rr.(*dns.NS); ok {
				serverName = strings.TrimSuffix(ns.Ns, ".")
				// Try to get glue record
				for _, extra := range resp.Extra {
					if a, ok := extra.(*dns.A); ok && a.Hdr.Name == ns.Ns {
						nextServer = a.A.String()
						break
					}
				}
				if nextServer == "" {
					// Resolve NS
					ips, _ := net.LookupHost(serverName)
					if len(ips) > 0 {
						nextServer = ips[0]
					}
				}
				if nextServer != "" {
					break
				}
			}
		}

		if serverName != "" {
			steps = append(steps, TraceStep{Zone: zone, Server: serverName})
		}

		if nextServer != "" {
			currentServer = nextServer
		}
	}

	return steps, nil
}

func (r *Resolver) getRootServerName(ip string) string {
	rootNames := map[string]string{
		"198.41.0.4":   "a.root-servers.net",
		"199.9.14.201": "b.root-servers.net",
		"192.33.4.12":  "c.root-servers.net",
	}
	if name, ok := rootNames[ip]; ok {
		return name
	}
	return ip
}

// ASNInfo holds information about an IP's autonomous system
type ASNInfo struct {
	ASN  string
	Org  string
}

// LookupASN returns ASN info for an IP address using Team Cymru's DNS service
func (r *Resolver) LookupASN(ip string) *ASNInfo {
	var query string
	if strings.Contains(ip, ":") {
		// IPv6: expand to full form, reverse nibbles, query origin6.asn.cymru.com
		addr := net.ParseIP(ip)
		if addr == nil {
			return nil
		}
		// Expand to 32 hex nibbles
		full := addr.To16()
		if full == nil {
			return nil
		}
		var nibbles []string
		for i := len(full) - 1; i >= 0; i-- {
			nibbles = append(nibbles, fmt.Sprintf("%x", full[i]&0x0f))
			nibbles = append(nibbles, fmt.Sprintf("%x", full[i]>>4))
		}
		query = strings.Join(nibbles, ".") + ".origin6.asn.cymru.com."
	} else {
		// IPv4: reverse octets, query origin.asn.cymru.com
		parts := strings.Split(ip, ".")
		if len(parts) != 4 {
			return nil
		}
		reversed := parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0]
		query = reversed + ".origin.asn.cymru.com."
	}

	m := new(dns.Msg)
	m.SetQuestion(query, dns.TypeTXT)
	m.RecursionDesired = true

	resp, _, err := r.client.Exchange(m, "8.8.8.8:53")
	if err != nil || len(resp.Answer) == 0 {
		return nil
	}

	txt, ok := resp.Answer[0].(*dns.TXT)
	if !ok || len(txt.Txt) == 0 {
		return nil
	}

	// Format: "ASN | prefix | CC | registry | date"
	fields := strings.SplitN(txt.Txt[0], " | ", 5)
	if len(fields) < 1 {
		return nil
	}

	asn := strings.TrimSpace(fields[0])
	return r.lookupASName(asn)
}

func (r *Resolver) lookupASName(asn string) *ASNInfo {
	nameQuery := fmt.Sprintf("AS%s.asn.cymru.com.", asn)
	m := new(dns.Msg)
	m.SetQuestion(nameQuery, dns.TypeTXT)
	m.RecursionDesired = true

	resp, _, err := r.client.Exchange(m, "8.8.8.8:53")
	if err != nil || len(resp.Answer) == 0 {
		return &ASNInfo{ASN: "AS" + asn}
	}

	txt, ok := resp.Answer[0].(*dns.TXT)
	if !ok || len(txt.Txt) == 0 {
		return &ASNInfo{ASN: "AS" + asn}
	}

	// Format: "ASN | CC | registry | date | description"
	nameFields := strings.SplitN(txt.Txt[0], " | ", 5)
	org := ""
	if len(nameFields) >= 5 {
		org = strings.TrimSpace(nameFields[4])
	}

	return &ASNInfo{ASN: "AS" + asn, Org: org}
}

// ReverseLookup returns the PTR hostname for an IP address, or empty string on failure
func (r *Resolver) ReverseLookup(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

// GetRecords fetches common DNS records for a domain
func (r *Resolver) GetRecords(domain string) (*Records, error) {
	domain = dns.Fqdn(domain)
	records := &Records{}

	// Fetch A records
	records.A = r.queryRecords(domain, dns.TypeA)

	// Fetch AAAA records
	records.AAAA = r.queryRecords(domain, dns.TypeAAAA)

	// Fetch MX records
	records.MX = r.queryMX(domain)

	// Fetch TXT records (condensed)
	records.TXT = r.queryTXT(domain)

	// Fetch CNAME
	records.CNAME = r.queryRecords(domain, dns.TypeCNAME)

	return records, nil
}

func (r *Resolver) queryRecords(domain string, qtype uint16) []string {
	m := new(dns.Msg)
	m.SetQuestion(domain, qtype)
	m.RecursionDesired = true

	resp, _, err := r.client.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return nil
	}

	var results []string
	for _, ans := range resp.Answer {
		switch rr := ans.(type) {
		case *dns.A:
			results = append(results, rr.A.String())
		case *dns.AAAA:
			results = append(results, rr.AAAA.String())
		case *dns.CNAME:
			results = append(results, strings.TrimSuffix(rr.Target, "."))
		}
	}
	return results
}

func (r *Resolver) queryMX(domain string) []string {
	m := new(dns.Msg)
	m.SetQuestion(domain, dns.TypeMX)
	m.RecursionDesired = true

	resp, _, err := r.client.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return nil
	}

	var results []string
	for _, ans := range resp.Answer {
		if mx, ok := ans.(*dns.MX); ok {
			results = append(results, fmt.Sprintf("%d %s", mx.Preference, strings.TrimSuffix(mx.Mx, ".")))
		}
	}
	return results
}

func (r *Resolver) queryTXT(domain string) []string {
	m := new(dns.Msg)
	m.SetQuestion(domain, dns.TypeTXT)
	m.RecursionDesired = true

	resp, _, err := r.client.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return nil
	}

	var results []string
	for _, ans := range resp.Answer {
		if txt, ok := ans.(*dns.TXT); ok {
			value := strings.Join(txt.Txt, "")
			// Truncate long TXT records
			if len(value) > 60 {
				value = value[:57] + "..."
			}
			results = append(results, value)
		}
	}
	return results
}
