package provider

import (
	"regexp"
	"strings"
)

// Pattern represents a regex pattern and its associated provider name
type Pattern struct {
	Regex    *regexp.Regexp
	Provider string
}

// Matcher identifies DNS providers from nameserver hostnames
type Matcher struct {
	patterns []Pattern
}

// Built-in provider patterns for common DNS providers
var builtinPatterns = []struct {
	pattern  string
	provider string
}{
	// Major cloud providers
	{`\.awsdns-\d+\.(com|net|org|co\.uk)$`, "Amazon Route 53"},
	{`\.azure-dns\.(com|net|org|info)$`, "Microsoft Azure DNS"},
	{`ns\d*\.google\.com$`, "Google Cloud DNS"},
	{`\.googledomains\.com$`, "Google Domains"},
	{`\.cloudflare\.com$`, "Cloudflare"},
	{`\.akam\.net$`, "Akamai"},
	{`\.akamai(dns|edge)?\.net$`, "Akamai"},

	// Domain registrars
	{`\.domaincontrol\.com$`, "GoDaddy"},
	{`\.godaddy\.com$`, "GoDaddy"},
	{`\.registrar-servers\.com$`, "Namecheap"},
	{`\.namecheaphosting\.com$`, "Namecheap"},
	{`dns\d*\.name-services\.com$`, "Enom"},
	{`\.enom\.com$`, "Enom"},
	{`\.hover\.com$`, "Hover"},
	{`\.name\.com$`, "Name.com"},
	{`\.gandi\.net$`, "Gandi"},
	{`\.ovh\.(net|com)$`, "OVH"},
	{`\.dnsimple\.com$`, "DNSimple"},
	{`\.porkbun\.com$`, "Porkbun"},
	{`\.dynadot\.com$`, "Dynadot"},
	{`\.ionos\.(com|de)$`, "IONOS"},

	// Hosting providers
	{`\.digitalocean\.com$`, "DigitalOcean"},
	{`\.linode\.com$`, "Linode (Akamai)"},
	{`\.vultr\.com$`, "Vultr"},
	{`\.hetzner\.(com|de)$`, "Hetzner"},
	{`\.scw\.cloud$`, "Scaleway"},
	{`\.rackspace\.com$`, "Rackspace"},
	{`\.dreamhost\.com$`, "DreamHost"},
	{`\.bluehost\.com$`, "Bluehost"},
	{`\.hostgator\.com$`, "HostGator"},
	{`\.siteground\.com$`, "SiteGround"},
	{`\.wpengine\.com$`, "WP Engine"},
	{`\.kinsta\.cloud$`, "Kinsta"},
	{`\.netlify\.com$`, "Netlify"},
	{`\.vercel-dns\.com$`, "Vercel"},

	// DNS service providers
	{`\.dnsmadeeasy\.com$`, "DNS Made Easy"},
	{`\.ultradns\.(com|net|org|biz)$`, "Neustar UltraDNS"},
	{`\.nsone\.net$`, "NS1"},
	{`\.p\d+\.dynect\.net$`, "Oracle Dyn"},
	{`\.dynect\.net$`, "Oracle Dyn"},
	{`\.easydns\.(com|net|org)$`, "easyDNS"},
	{`\.constellix\.com$`, "Constellix"},
	{`\.rage4\.com$`, "Rage4"},
	{`\.he\.net$`, "Hurricane Electric"},
	{`\.afraid\.org$`, "FreeDNS (afraid.org)"},
	{`\.no-ip\.com$`, "No-IP"},
	{`\.dyn\.com$`, "Oracle Dyn"},
	{`\.zoneedit\.com$`, "ZoneEdit"},
	{`\.dnspod\.net$`, "DNSPod (Tencent)"},
	{`\.edgedns\.net$`, "Akamai Edge DNS"},
	{`\.hyp\.net$`, "Domeneshop"},

	// CDN providers
	{`\.fastly\.net$`, "Fastly"},
	{`\.stackpathdns\.com$`, "StackPath"},
	{`\.leaseweb\.(com|net)$`, "Leaseweb"},

	// Enterprise / ISP
	{`\.worldnic\.com$`, "Network Solutions"},
	{`\.networksolutions\.com$`, "Network Solutions"},
	{`\.verisign-grs\.com$`, "Verisign"},
	{`\.cscdns\.net$`, "CSC"},
	{`\.markmonitor\.com$`, "MarkMonitor"},
	{`\.safenames\.net$`, "Safenames"},

	// Regional / Country-specific
	{`\.domeneshop\.no$`, "Domeneshop"},
	{`\.transip\.nl$`, "TransIP"},
	{`\.strato\.(de|com)$`, "Strato"},
	{`\.1und1\.de$`, "1&1 IONOS"},
	{`\.loopia\.se$`, "Loopia"},
	{`\.one\.com$`, "one.com"},
	{`\.binero\.se$`, "Binero"},
	{`\.active24\.(cz|com)$`, "Active24"},

	// Telecom / ISP DNS
	{`\.teliacompany\.com$`, "Telia"},
	{`\.telia\.net$`, "Telia"},
	{`\.telenor\.(net|com|no)$`, "Telenor"},
	{`\.altibox\.net$`, "Altibox"},
}

// Built-in infrastructure patterns for A record reverse DNS and CNAME targets
var builtinInfraPatterns = []struct {
	pattern  string
	provider string
}{
	// CDN
	{`\.cloudfront\.net$`, "Amazon CloudFront"},
	{`\.cdn\.cloudflare\.net$`, "Cloudflare"},
	{`\.fastly\.net$`, "Fastly"},
	{`\.akamaiedge\.net$`, "Akamai"},
	{`\.akamai\.net$`, "Akamai"},
	{`\.edgekey\.net$`, "Akamai"},

	// Cloud providers
	{`\.amazonaws\.com$`, "AWS"},
	{`\.1e100\.net$`, "Google"},
	{`\.azureedge\.net$`, "Azure CDN"},
	{`\.googleusercontent\.com$`, "Google Cloud"},
	{`\.azure\.com$`, "Microsoft Azure"},

	// Hosting / VPS providers
	{`\.scaleway\.com$`, "Scaleway"},
	{`\.scw\.cloud$`, "Scaleway"},
	{`\.ovh\.(net|com)$`, "OVH"},
	{`\.hetzner\.(com|de|cloud)$`, "Hetzner"},

	// Hosting platforms
	{`\.github\.io$`, "GitHub Pages"},
	{`\.netlify\.app$`, "Netlify"},
	{`\.netlify\.com$`, "Netlify"},
	{`\.vercel-dns\.com$`, "Vercel"},
	{`\.vercel\.app$`, "Vercel"},
	{`\.herokuapp\.com$`, "Heroku"},
	{`\.shopify\.com$`, "Shopify"},
	{`\.squarespace\.com$`, "Squarespace"},
	{`\.wixdns\.net$`, "Wix"},
	{`\.wpengine\.com$`, "WP Engine"},
	{`\.fly\.dev$`, "Fly.io"},

	// Security / WAF
	{`\.incapdns\.net$`, "Imperva"},
	{`\.sucuri\.net$`, "Sucuri"},
}

// Built-in mail patterns for MX record hostnames
var builtinMailPatterns = []struct {
	pattern  string
	provider string
}{
	{`aspmx.*\.google\.com$`, "Google Workspace"},
	{`googlemail\.com$`, "Google Workspace"},
	{`\.google\.com$`, "Google Workspace"},
	{`protection\.outlook\.com$`, "Microsoft 365"},
	{`mail\.protection\.outlook\.com$`, "Microsoft 365"},
	{`\.pphosted\.com$`, "Proofpoint"},
	{`\.mimecast\.com$`, "Mimecast"},
	{`\.mailgun\.org$`, "Mailgun"},
	{`\.sendgrid\.net$`, "Twilio SendGrid"},
	{`\.amazonses\.com$`, "Amazon SES"},
	{`\.zoho\.com$`, "Zoho Mail"},
	{`\.icloud\.com$`, "Apple iCloud"},
	{`\.fastmail\.com$`, "Fastmail"},
	{`\.protonmail\.ch$`, "Proton Mail"},
	{`\.secureserver\.net$`, "GoDaddy"},
	{`\.emailsrvr\.com$`, "Rackspace Email"},
}

// NewMatcher creates a new provider matcher with built-in patterns
func NewMatcher() *Matcher {
	return newMatcherFrom(builtinPatterns)
}

// NewInfraMatcher creates a matcher for infrastructure providers (A record reverse DNS, CNAME targets)
func NewInfraMatcher() *Matcher {
	return newMatcherFrom(builtinInfraPatterns)
}

// NewMailMatcher creates a matcher for mail providers (MX record hostnames)
func NewMailMatcher() *Matcher {
	return newMatcherFrom(builtinMailPatterns)
}

func newMatcherFrom(patterns []struct {
	pattern  string
	provider string
}) *Matcher {
	m := &Matcher{
		patterns: make([]Pattern, 0, len(patterns)),
	}

	for _, bp := range patterns {
		re, err := regexp.Compile("(?i)" + bp.pattern)
		if err != nil {
			continue
		}
		m.patterns = append(m.patterns, Pattern{
			Regex:    re,
			Provider: bp.provider,
		})
	}

	return m
}

// AddPattern adds a custom pattern to the matcher
// Format: "pattern:provider" (e.g., "\.mycompany\.com$:My Company")
func (m *Matcher) AddPattern(patternSpec string) error {
	parts := strings.SplitN(patternSpec, ":", 2)
	if len(parts) != 2 {
		return &PatternError{Pattern: patternSpec, Message: "invalid format, expected 'pattern:provider'"}
	}

	pattern := strings.TrimSpace(parts[0])
	provider := strings.TrimSpace(parts[1])

	if pattern == "" || provider == "" {
		return &PatternError{Pattern: patternSpec, Message: "pattern and provider cannot be empty"}
	}

	re, err := regexp.Compile("(?i)" + pattern)
	if err != nil {
		return &PatternError{Pattern: pattern, Message: err.Error()}
	}

	// Add custom patterns at the beginning so they take precedence
	m.patterns = append([]Pattern{{Regex: re, Provider: provider}}, m.patterns...)
	return nil
}

// AddPatterns adds multiple custom patterns
func (m *Matcher) AddPatterns(patternSpecs []string) []error {
	var errors []error
	for _, spec := range patternSpecs {
		if err := m.AddPattern(spec); err != nil {
			errors = append(errors, err)
		}
	}
	return errors
}

// Match returns the provider name for a nameserver hostname
// Returns empty string if no match found
func (m *Matcher) Match(nameserver string) string {
	ns := strings.ToLower(nameserver)

	for _, p := range m.patterns {
		if p.Regex.MatchString(ns) {
			return p.Provider
		}
	}

	return ""
}

// PatternError represents an error with a pattern specification
type PatternError struct {
	Pattern string
	Message string
}

func (e *PatternError) Error() string {
	return "invalid pattern '" + e.Pattern + "': " + e.Message
}
