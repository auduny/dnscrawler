package cmd

import (
	"fmt"
	"os"
	"strings"

	"dnscrawler/pkg/dns"
	"dnscrawler/pkg/domain"
	"dnscrawler/pkg/output"
	"dnscrawler/pkg/provider"
	"dnscrawler/pkg/whois"

	"github.com/spf13/cobra"
)

var (
	noWhois          bool
	noTrace          bool
	providerPatterns []string
)

var rootCmd = &cobra.Command{
	Use:   "dnscrawler <domain>",
	Short: "Get condensed DNS and WHOIS information for a domain",
	Long: `dnscrawler provides a quick overview of DNS and WHOIS information
for any domain, including authoritative nameservers, DNS trace,
key records, and registration details.`,
	Args: cobra.ExactArgs(1),
	Run:  runCrawler,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().BoolVar(&noWhois, "no-whois", false, "Skip WHOIS lookup")
	rootCmd.Flags().BoolVar(&noTrace, "no-trace", false, "Skip DNS trace")
	rootCmd.Flags().StringArrayVarP(&providerPatterns, "provider", "p", nil,
		"Custom provider pattern in format 'regex:name' (e.g., '\\.mycompany\\.com$:My Company')")
}

func runCrawler(cmd *cobra.Command, args []string) {
	domainArg := strings.ToLower(strings.TrimSpace(args[0]))
	// Remove protocol if present
	domainArg = strings.TrimPrefix(domainArg, "http://")
	domainArg = strings.TrimPrefix(domainArg, "https://")
	// Remove path if present
	if idx := strings.Index(domainArg, "/"); idx > 0 {
		domainArg = domainArg[:idx]
	}

	formatter := output.New()
	resolver := dns.NewResolver()
	whoisClient := whois.NewClient()

	// Setup provider matchers
	providerMatcher := provider.NewMatcher()
	if len(providerPatterns) > 0 {
		errs := providerMatcher.AddPatterns(providerPatterns)
		for _, err := range errs {
			formatter.PrintError(fmt.Sprintf("invalid pattern: %v", err))
		}
	}
	infraMatcher := provider.NewInfraMatcher()
	mailMatcher := provider.NewMailMatcher()

	// Check if this is a subdomain
	rootDomain := domain.GetRootDomain(domainArg)
	isSubdomain := domain.IsSubdomain(domainArg)

	// If subdomain, first show root domain info
	if isSubdomain {
		printDomainInfo(formatter, resolver, whoisClient, providerMatcher, infraMatcher, mailMatcher, rootDomain, true)
	}

	// Show info for the requested domain
	printDomainInfo(formatter, resolver, whoisClient, providerMatcher, infraMatcher, mailMatcher, domainArg, false)

	formatter.Finish()
}

func printDomainInfo(formatter *output.Formatter, resolver *dns.Resolver, whoisClient *whois.Client, providerMatcher *provider.Matcher, infraMatcher *provider.Matcher, mailMatcher *provider.Matcher, domainName string, isRootContext bool) {
	if isRootContext {
		formatter.PrintTitle(domainName + " (root domain)")
	} else {
		formatter.PrintTitle(domainName)
	}

	// Check if domain exists
	if !resolver.Exists(domainName) {
		formatter.PrintDim("Domain not registered")
		return
	}

	// WHOIS Information
	if !noWhois {
		info, err := whoisClient.Lookup(domainName)
		if err != nil {
			formatter.PrintSection("WHOIS")
			formatter.PrintError(fmt.Sprintf("lookup failed: %v", err))
		} else {
			printWhoisInfo(formatter, info)
		}
	}

	// Nameservers
	formatter.PrintSection("NAMESERVERS")
	nameservers, err := resolver.GetNameservers(domainName)
	if err != nil {
		formatter.PrintError(fmt.Sprintf("lookup failed: %v", err))
	} else if len(nameservers) == 0 {
		formatter.PrintDim("No nameservers found")
	} else {
		for _, ns := range nameservers {
			providerName := providerMatcher.Match(ns.Name)
			nsDisplay := ns.Name
			if ns.IP != "" {
				nsDisplay = fmt.Sprintf("%s (%s)", ns.Name, ns.IP)
			}
			asn := ""
			if ns.IP != "" {
				if info := resolver.LookupASN(ns.IP); info != nil {
					asn = info.ASN
					if info.Org != "" {
						asn = info.Org
					}
				}
			}
			formatter.PrintArrowItemWithProviderAndASN(nsDisplay, providerName, asn)
		}
	}

	// DNS Trace (skip for root context to reduce noise)
	if !noTrace && !isRootContext {
		formatter.PrintSection("DNS TRACE")
		steps, err := resolver.Trace(domainName)
		if err != nil {
			formatter.PrintError(fmt.Sprintf("trace failed: %v", err))
		} else if len(steps) == 0 {
			formatter.PrintDim("No trace data")
		} else {
			for _, step := range steps {
				formatter.PrintTraceStep(step.Zone, step.Server)
			}
		}
	}

	// DNS Records
	formatter.PrintSection("RECORDS")
	records, err := resolver.GetRecords(domainName)
	if err != nil {
		formatter.PrintError(fmt.Sprintf("lookup failed: %v", err))
	} else {
		printRecords(formatter, resolver, infraMatcher, mailMatcher, records)
	}
}

func printWhoisInfo(formatter *output.Formatter, info *whois.Info) {
	if info.Registry != "" {
		formatter.PrintKeyValue("REGISTRY", info.Registry)
	}
	if info.Registrar != "" {
		formatter.PrintKeyValue("REGISTRAR", info.Registrar)
	}
	if info.Registrant != "" {
		formatter.PrintKeyValue("REGISTRANT", info.Registrant)
	}
	if info.Created != "" {
		formatter.PrintKeyValue("CREATED", info.Created)
	}
	if info.Expires != "" {
		formatter.PrintKeyValue("EXPIRES", info.Expires)
	}
	if len(info.Status) > 0 {
		// Show first few status codes
		statusStr := strings.Join(info.Status, ", ")
		if len(statusStr) > 50 {
			statusStr = strings.Join(info.Status[:min(3, len(info.Status))], ", ")
			if len(info.Status) > 3 {
				statusStr += "..."
			}
		}
		formatter.PrintKeyValue("STATUS", statusStr)
	}
}

func printRecords(formatter *output.Formatter, resolver *dns.Resolver, infraMatcher *provider.Matcher, mailMatcher *provider.Matcher, records *dns.Records) {
	hasRecords := false

	for _, cname := range records.CNAME {
		prov := infraMatcher.Match(cname)
		formatter.PrintRecordWithProvider("CNAME", cname, prov)
		hasRecords = true
	}

	for _, a := range records.A {
		prov := ""
		if hostname := resolver.ReverseLookup(a); hostname != "" {
			if p := infraMatcher.Match(hostname); p != "" {
				prov = p
			} else {
				prov = strings.TrimRight(hostname, ".")
			}
		}
		asn := ""
		if info := resolver.LookupASN(a); info != nil {
			asn = info.ASN
			if info.Org != "" {
				asn = info.Org
			}
		}
		formatter.PrintRecordWithProviderAndASN("A", a, prov, asn)
		hasRecords = true
	}

	for _, aaaa := range records.AAAA {
		prov := ""
		if hostname := resolver.ReverseLookup(aaaa); hostname != "" {
			if p := infraMatcher.Match(hostname); p != "" {
				prov = p
			} else {
				prov = strings.TrimRight(hostname, ".")
			}
		}
		asn := ""
		if info := resolver.LookupASN(aaaa); info != nil {
			asn = info.ASN
			if info.Org != "" {
				asn = info.Org
			}
		}
		formatter.PrintRecordWithProviderAndASN("AAAA", aaaa, prov, asn)
		hasRecords = true
	}

	for _, mx := range records.MX {
		// MX format is "priority hostname" — match against the hostname part
		prov := mailMatcher.Match(mx)
		formatter.PrintRecordWithProvider("MX", mx, prov)
		hasRecords = true
	}

	for _, txt := range records.TXT {
		formatter.PrintRecord("TXT", txt)
		hasRecords = true
	}

	if !hasRecords {
		formatter.PrintDim("No records found")
	}
}
