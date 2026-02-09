package whois

import (
	"io"
	"net"
	"strings"
	"time"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
)

type Info struct {
	Registrar   string
	Registry    string // TLD operator (separate from registrar)
	Created     string
	Updated     string
	Expires     string
	Status      []string
	Registrant  string
	NameServers []string
}

type Client struct{}

func NewClient() *Client {
	return &Client{}
}

func (c *Client) Lookup(domain string) (*Info, error) {
	tld := getTLD(domain)

	// Get raw WHOIS data
	rawWhois, err := whois.Whois(domain)
	if err != nil {
		// If WHOIS fails, return registry info only
		info := &Info{}
		if registry, ok := gTLDRegistries[tld]; ok {
			info.Registry = registry
		} else if registry, ok := ccTLDRegistries[tld]; ok {
			info.Registry = registry
		}
		if info.Registry != "" {
			return info, nil
		}
		return nil, err
	}

	// Parse the WHOIS response
	parsed, err := whoisparser.Parse(rawWhois)
	if err != nil {
		// Return partial info if parsing fails
		return c.parseRawWhois(rawWhois, domain), nil
	}

	info := &Info{
		Created: formatDate(parsed.Domain.CreatedDate),
		Updated: formatDate(parsed.Domain.UpdatedDate),
		Expires: formatDate(parsed.Domain.ExpirationDate),
		Status:  parseStatus(parsed.Domain.Status),
	}

	if parsed.Registrar != nil {
		info.Registrar = parsed.Registrar.Name
	}

	if parsed.Registrant != nil {
		if parsed.Registrant.Organization != "" {
			info.Registrant = parsed.Registrant.Organization
		} else if parsed.Registrant.Name != "" {
			info.Registrant = parsed.Registrant.Name
		}
	}

	info.NameServers = parsed.Domain.NameServers

	// Supplement with raw parsing for fields the parser missed
	if info.Registrar == "" || info.Created == "" {
		raw := c.parseRawWhois(rawWhois, domain)
		if info.Registrar == "" {
			info.Registrar = raw.Registrar
		}
		if info.Created == "" {
			info.Created = raw.Created
		}
		if info.Updated == "" {
			info.Updated = raw.Updated
		}
	}

	// Resolve registrar handle to company name if needed
	info.Registrar = c.resolveRegistrarHandle(info.Registrar, tld)

	// Set registry info (TLD operator) - separate from registrar
	if registry, ok := gTLDRegistries[tld]; ok {
		info.Registry = registry
	} else if registry, ok := ccTLDRegistries[tld]; ok {
		info.Registry = registry
	}

	return info, nil
}

// resolveRegistrarHandle looks up registrar handles to get the actual company name
func (c *Client) resolveRegistrarHandle(handle string, tld string) string {
	if handle == "" {
		return ""
	}

	// Norid (.no) - handles end with -NORID
	if strings.HasSuffix(handle, "-NORID") && tld == "no" {
		if name := c.lookupNoridRegistrar(handle); name != "" {
			return name
		}
	}

	// Nominet (.uk) - format is "Company Name [Tag = XXX]"
	// Extract just the company name
	if tld == "uk" && strings.Contains(handle, "[Tag = ") {
		if idx := strings.Index(handle, " [Tag = "); idx > 0 {
			return strings.TrimSpace(handle[:idx])
		}
	}

	return handle
}

// lookupNoridRegistrar queries Norid's WHOIS for registrar details
func (c *Client) lookupNoridRegistrar(handle string) string {
	// Direct TCP connection to Norid's WHOIS server
	// (the whois library doesn't reliably use custom servers)
	conn, err := net.DialTimeout("tcp", "whois.norid.no:43", 5*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write([]byte(handle + "\r\n"))
	if err != nil {
		return ""
	}

	response, err := io.ReadAll(conn)
	if err != nil {
		return ""
	}

	// Parse the response to find the registrar name
	// Norid format: "Registrar Name.............: Company Name"
	lines := strings.Split(string(response), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Registrar Name") && strings.Contains(line, ":") {
			if idx := strings.LastIndex(line, ":"); idx > 0 {
				name := strings.TrimSpace(line[idx+1:])
				if name != "" {
					return name
				}
			}
		}
	}

	return ""
}

// gTLD registries - new generic TLDs (often RDAP-only, no traditional WHOIS)
var gTLDRegistries = map[string]string{
	// Google Registry
	"dev":     "Google Registry",
	"app":     "Google Registry",
	"page":    "Google Registry",
	"how":     "Google Registry",
	"soy":     "Google Registry",
	"chrome":  "Google Registry",
	"google":  "Google Registry",
	"gmail":   "Google Registry",
	"youtube": "Google Registry",
	"android": "Google Registry",
	"docs":    "Google Registry",
	"drive":   "Google Registry",
	"play":    "Google Registry",
	"new":     "Google Registry",
	"day":     "Google Registry",
	"rsvp":    "Google Registry",
	"foo":     "Google Registry",
	"zip":     "Google Registry",
	"mov":     "Google Registry",
	"nexus":   "Google Registry",
	"dad":     "Google Registry",
	"phd":     "Google Registry",
	"prof":    "Google Registry",
	"esq":     "Google Registry",
	"meme":    "Google Registry",
	"ing":     "Google Registry",

	// Amazon Registry
	"aws":     "Amazon Registry",
	"amazon":  "Amazon Registry",
	"audible": "Amazon Registry",
	"book":    "Amazon Registry",
	"bot":     "Amazon Registry",
	"buy":     "Amazon Registry",
	"fire":    "Amazon Registry",
	"free":    "Amazon Registry",
	"got":     "Amazon Registry",
	"imdb":    "Amazon Registry",
	"joy":     "Amazon Registry",
	"kindle":  "Amazon Registry",
	"like":    "Amazon Registry",
	"mobile":  "Amazon Registry",
	"now":     "Amazon Registry",
	"pay":     "Amazon Registry",
	"pin":     "Amazon Registry",
	"prime":   "Amazon Registry",
	"read":    "Amazon Registry",
	"room":    "Amazon Registry",
	"safe":    "Amazon Registry",
	"save":    "Amazon Registry",
	"silk":    "Amazon Registry",
	"smile":   "Amazon Registry",
	"spot":    "Amazon Registry",
	"talk":    "Amazon Registry",
	"tunes":   "Amazon Registry",
	"wow":     "Amazon Registry",

	// Cloudflare
	"stream": "Cloudflare",

	// Identity Digital (Donuts)
	"tech":     "Identity Digital",
	"online":   "Identity Digital",
	"site":     "Identity Digital",
	"store":    "Identity Digital",
	"fun":      "Identity Digital",
	"space":    "Identity Digital",
	"live":     "Identity Digital",
	"news":     "Identity Digital",
	"world":    "Identity Digital",
	"email":    "Identity Digital",
	"cloud":    "Identity Digital",
	"digital":  "Identity Digital",
	"network":  "Identity Digital",
	"software": "Identity Digital",
	"systems":  "Identity Digital",
	"agency":   "Identity Digital",
	"studio":   "Identity Digital",
	"design":   "Identity Digital",
	"codes":    "Identity Digital",
	"tools":    "Identity Digital",
	"zone":     "Identity Digital",
	"rocks":    "Identity Digital",
	"run":      "Identity Digital",

	// Radix
	"website": "Radix",
	"host":    "Radix",
	"press":   "Radix",

	// Other
	"xyz":  "XYZ.COM",
	"club": "Registry Services, LLC",
	"top":  "Jiangsu Bangning",
	"icu":  "ShortDot",
	"cyou": "ShortDot",
	"cfd":  "ShortDot",
	"sbs":  "ShortDot",
	"bond": "ShortDot",
}

// ccTLD registries - shown when WHOIS doesn't expose registrar info
var ccTLDRegistries = map[string]string{
	// Europe
	"no": "Norid",
	"dk": "Punktum dk",
	"de": "DENIC",
	"se": "Internetstiftelsen",
	"fi": "Traficom",
	"nl": "SIDN",
	"be": "DNS Belgium",
	"at": "nic.at",
	"ch": "SWITCH",
	"li": "SWITCH",
	"pl": "NASK",
	"cz": "CZ.NIC",
	"sk": "SK-NIC",
	"hu": "ISZT",
	"ro": "ROTLD",
	"bg": "Register.BG",
	"hr": "CARNET",
	"si": "ARNES",
	"rs": "RNIDS",
	"ua": "UA-NIC",
	"ru": "CCTLD.RU",
	"by": "BY-NIC",
	"lt": "DOMREG",
	"lv": "NIC.LV",
	"ee": "EIS",
	"is": "ISNIC",
	"ie": "IEDR",
	"pt": "DNS.PT",
	"es": "Red.es",
	"it": "NIC.IT",
	"fr": "AFNIC",
	"gr": "GRNET",
	"eu": "EURid",
	"uk": "Nominet",

	// Asia
	"jp": "JPRS",
	"cn": "CNNIC",
	"kr": "KISA",
	"tw": "TWNIC",
	"hk": "HKDNR",
	"sg": "SGNIC",
	"my": "MYNIC",
	"th": "THNIC",
	"vn": "VNNIC",
	"id": "PANDI",
	"ph": "dotPH",
	"in": "NIXI",
	"pk": "PKNIC",
	"bd": "BTCL",
	"np": "Mercantile",
	"lk": "LK Domain Registry",
	"kz": "KazNIC",
	"uz": "UZINFOCOM",
	"ae": "AEDA",
	"sa": "SaudiNIC",
	"il": "ISOC-IL",
	"tr": "NIC.TR",
	"ir": "IRNIC",

	// Oceania
	"au": "auDA",
	"nz": "InternetNZ",
	"fj": "DOMAINS.FJ",

	// Americas
	"ca": "CIRA",
	"mx": "NIC Mexico",
	"br": "Registro.br",
	"ar": "NIC Argentina",
	"cl": "NIC Chile",
	"co": "CO Internet",
	"pe": "NIC.PE",
	"ve": "NIC.VE",
	"uy": "NIC.UY",
	"py": "NIC.PY",
	"ec": "NIC.EC",

	// Africa
	"za": "ZADNA",
	"ng": "NiRA",
	"ke": "KENIC",
	"eg": "EGNIC",
	"ma": "ANRT",
	"tn": "ATI",
	"gh": "NIC.GH",
	"tz": "tzNIC",
	"ug": "REGISTRY.CO.UG",
	"et": "ETNIC",
	"mu": "NIC.MU",
}

func (c *Client) parseRawWhois(raw string, domain string) *Info {
	info := &Info{}
	lines := strings.Split(raw, "\n")
	tld := getTLD(domain)

	// Set registry info
	if registry, ok := gTLDRegistries[tld]; ok {
		info.Registry = registry
	} else if registry, ok := ccTLDRegistries[tld]; ok {
		info.Registry = registry
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Standard WHOIS format
		if strings.HasPrefix(line, "Registrar:") && info.Registrar == "" {
			info.Registrar = strings.TrimSpace(strings.TrimPrefix(line, "Registrar:"))
		} else if strings.HasPrefix(line, "Sponsoring Registrar:") && info.Registrar == "" {
			info.Registrar = strings.TrimSpace(strings.TrimPrefix(line, "Sponsoring Registrar:"))
		} else if strings.HasPrefix(line, "Creation Date:") && info.Created == "" {
			info.Created = formatDate(strings.TrimSpace(strings.TrimPrefix(line, "Creation Date:")))
		} else if strings.HasPrefix(line, "Registry Expiry Date:") && info.Expires == "" {
			info.Expires = formatDate(strings.TrimSpace(strings.TrimPrefix(line, "Registry Expiry Date:")))
		} else if strings.HasPrefix(line, "Domain Status:") {
			status := strings.TrimSpace(strings.TrimPrefix(line, "Domain Status:"))
			if idx := strings.Index(status, " "); idx > 0 {
				status = status[:idx]
			}
			info.Status = append(info.Status, status)
		}

		// Norid (.no) format - registrar handle
		if strings.HasPrefix(line, "Registrar Handle") && info.Registrar == "" {
			// Format is "Registrar Handle...: REG123-NORID"
			if idx := strings.LastIndex(line, ":"); idx > 0 {
				info.Registrar = strings.TrimSpace(line[idx+1:])
			}
		}

		// Generic date formats
		if strings.HasPrefix(line, "Created:") && info.Created == "" {
			info.Created = formatDate(strings.TrimSpace(strings.TrimPrefix(line, "Created:")))
		} else if strings.HasPrefix(line, "Last updated:") && info.Updated == "" {
			info.Updated = formatDate(strings.TrimSpace(strings.TrimPrefix(line, "Last updated:")))
		}

		// Punktum dk (.dk) format
		if strings.HasPrefix(line, "Registered:") && info.Created == "" {
			info.Created = formatDate(strings.TrimSpace(strings.TrimPrefix(line, "Registered:")))
		} else if strings.HasPrefix(line, "Expires:") && info.Expires == "" {
			info.Expires = formatDate(strings.TrimSpace(strings.TrimPrefix(line, "Expires:")))
		}

		// DENIC (.de) format
		if strings.HasPrefix(line, "Changed:") && info.Updated == "" {
			info.Updated = formatDate(strings.TrimSpace(strings.TrimPrefix(line, "Changed:")))
		}

		// AFNIC (.fr) format
		if strings.HasPrefix(line, "registrar:") && info.Registrar == "" {
			info.Registrar = strings.TrimSpace(strings.TrimPrefix(line, "registrar:"))
		} else if strings.HasPrefix(line, "created:") && info.Created == "" {
			info.Created = formatDate(strings.TrimSpace(strings.TrimPrefix(line, "created:")))
		}

		// UK format
		if strings.HasPrefix(line, "Registrar:") && info.Registrar == "" {
			info.Registrar = strings.TrimSpace(strings.TrimPrefix(line, "Registrar:"))
		} else if strings.HasPrefix(line, "Relevant dates:") {
			// Skip header
		} else if strings.Contains(line, "Registered on:") && info.Created == "" {
			if idx := strings.Index(line, "Registered on:"); idx >= 0 {
				info.Created = formatDate(strings.TrimSpace(line[idx+14:]))
			}
		} else if strings.Contains(line, "Expiry date:") && info.Expires == "" {
			if idx := strings.Index(line, "Expiry date:"); idx >= 0 {
				info.Expires = formatDate(strings.TrimSpace(line[idx+12:]))
			}
		}
	}

	return info
}

func getTLD(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}

func formatDate(date string) string {
	if date == "" {
		return ""
	}

	// UK format: "before Aug-1996" or "13-Dec-2034"
	// Keep these as-is since they're already readable
	if strings.Contains(date, "-") && !strings.HasPrefix(date, "20") && !strings.HasPrefix(date, "19") {
		// Check if it looks like UK format (DD-Mon-YYYY or "before Mon-YYYY")
		if strings.Contains(date, "Jan") || strings.Contains(date, "Feb") ||
			strings.Contains(date, "Mar") || strings.Contains(date, "Apr") ||
			strings.Contains(date, "May") || strings.Contains(date, "Jun") ||
			strings.Contains(date, "Jul") || strings.Contains(date, "Aug") ||
			strings.Contains(date, "Sep") || strings.Contains(date, "Oct") ||
			strings.Contains(date, "Nov") || strings.Contains(date, "Dec") {
			return date
		}
	}

	// ISO format: extract just the date part (YYYY-MM-DD)
	if len(date) >= 10 && (strings.HasPrefix(date, "20") || strings.HasPrefix(date, "19")) {
		return date[:10]
	}

	return date
}

func parseStatus(statuses []string) []string {
	var result []string
	seen := make(map[string]bool)

	for _, s := range statuses {
		// Extract just the status code without the URL
		status := s
		if idx := strings.Index(s, " "); idx > 0 {
			status = s[:idx]
		}
		// Deduplicate
		if !seen[status] {
			seen[status] = true
			result = append(result, status)
		}
	}

	return result
}
