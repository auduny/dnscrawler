package domain

import (
	"strings"
)

// Common multi-part TLDs (public suffix list subset)
var multiPartTLDs = map[string]bool{
	"co.uk":      true,
	"org.uk":     true,
	"me.uk":      true,
	"ac.uk":      true,
	"gov.uk":     true,
	"co.nz":      true,
	"org.nz":     true,
	"net.nz":     true,
	"co.jp":      true,
	"ne.jp":      true,
	"or.jp":      true,
	"ac.jp":      true,
	"com.au":     true,
	"net.au":     true,
	"org.au":     true,
	"edu.au":     true,
	"gov.au":     true,
	"co.za":      true,
	"org.za":     true,
	"com.br":     true,
	"org.br":     true,
	"net.br":     true,
	"gov.br":     true,
	"com.mx":     true,
	"org.mx":     true,
	"gob.mx":     true,
	"co.in":      true,
	"net.in":     true,
	"org.in":     true,
	"ac.in":      true,
	"gov.in":     true,
	"com.cn":     true,
	"net.cn":     true,
	"org.cn":     true,
	"gov.cn":     true,
	"com.tw":     true,
	"org.tw":     true,
	"gov.tw":     true,
	"co.kr":      true,
	"or.kr":      true,
	"ne.kr":      true,
	"com.sg":     true,
	"org.sg":     true,
	"edu.sg":     true,
	"gov.sg":     true,
	"com.my":     true,
	"org.my":     true,
	"gov.my":     true,
	"co.th":      true,
	"or.th":      true,
	"ac.th":      true,
	"go.th":      true,
	"com.ph":     true,
	"org.ph":     true,
	"gov.ph":     true,
	"com.vn":     true,
	"org.vn":     true,
	"gov.vn":     true,
	"co.id":      true,
	"or.id":      true,
	"ac.id":      true,
	"go.id":      true,
	"com.ar":     true,
	"org.ar":     true,
	"gov.ar":     true,
	"co.cl":      true,
	"com.co":     true,
	"org.co":     true,
	"gov.co":     true,
	"com.pe":     true,
	"org.pe":     true,
	"gob.pe":     true,
	"com.ve":     true,
	"org.ve":     true,
	"gob.ve":     true,
	"com.ec":     true,
	"org.ec":     true,
	"com.uy":     true,
	"org.uy":     true,
	"gub.uy":     true,
	"co.il":      true,
	"org.il":     true,
	"ac.il":      true,
	"gov.il":     true,
	"com.tr":     true,
	"org.tr":     true,
	"gov.tr":     true,
	"edu.tr":     true,
	"com.ua":     true,
	"org.ua":     true,
	"gov.ua":     true,
	"co.ke":      true,
	"or.ke":      true,
	"go.ke":      true,
	"co.tz":      true,
	"or.tz":      true,
	"go.tz":      true,
	"co.ug":      true,
	"or.ug":      true,
	"go.ug":      true,
	"com.ng":     true,
	"org.ng":     true,
	"gov.ng":     true,
	"com.eg":     true,
	"org.eg":     true,
	"gov.eg":     true,
	"com.sa":     true,
	"org.sa":     true,
	"gov.sa":     true,
	"com.ae":     true,
	"org.ae":     true,
	"gov.ae":     true,
	"com.pk":     true,
	"org.pk":     true,
	"gov.pk":     true,
	"govt.nz":    true,
	"ac.nz":      true,
	"com.pl":     true,
	"org.pl":     true,
	"gov.pl":     true,
	"net.pl":     true,
	"com.ru":     true,
	"org.ru":     true,
	"gov.ru":     true,
	"priv.no":    true,
	"fylke.no":   true,
	"kommune.no": true,
}

// GetRootDomain extracts the registrable/root domain from a full domain name
// e.g., "int.ytterdal.net" -> "ytterdal.net"
//
//	"www.example.co.uk" -> "example.co.uk"
func GetRootDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimSuffix(domain, ".")

	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return domain
	}

	// Check for multi-part TLD (e.g., co.uk)
	if len(parts) >= 3 {
		possibleTLD := parts[len(parts)-2] + "." + parts[len(parts)-1]
		if multiPartTLDs[possibleTLD] {
			// Domain with multi-part TLD: need at least 3 parts for root
			if len(parts) >= 3 {
				return parts[len(parts)-3] + "." + possibleTLD
			}
			return domain
		}
	}

	// Standard TLD: root domain is last 2 parts
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

// IsSubdomain checks if the domain is a subdomain (not the root domain)
func IsSubdomain(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimSuffix(domain, ".")

	rootDomain := GetRootDomain(domain)
	return domain != rootDomain
}

// GetParentDomain returns the parent domain (one level up)
// e.g., "sub.int.ytterdal.net" -> "int.ytterdal.net"
func GetParentDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimSuffix(domain, ".")

	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return domain
	}

	return strings.Join(parts[1:], ".")
}
