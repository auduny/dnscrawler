# dnscrawler

A command-line tool that gives you a condensed overview of any domain's DNS and WHOIS information in a single command.

```
$ dnscrawler example.com

example.com
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
REGISTRAR    RESERVED-Internet Assigned Numbers Authority
CREATED      1995-08-14
EXPIRES      2026-08-13
STATUS       clientDeleteProhibited, clientTransferProhibited, clientUpdateProhibited

NAMESERVERS
  → elliott.ns.cloudflare.com (162.159.44.228) [Cloudflare] (CLOUDFLARENET)
  → hera.ns.cloudflare.com (172.64.32.162) [Cloudflare] (CLOUDFLARENET)

DNS TRACE
  . → a.root-servers.net
  com. → l.gtld-servers.net
  example.com. → hera.ns.cloudflare.com

RECORDS
  A      104.18.27.120 (CLOUDFLARENET)
  A      104.18.26.120 (CLOUDFLARENET)
  AAAA   2606:4700::6812:1a78 (CLOUDFLARENET)
  AAAA   2606:4700::6812:1b78 (CLOUDFLARENET)
  MX     0 .
  TXT    v=spf1 -all
```

## What it shows

- **WHOIS** -- registrar, registry, registrant, creation/expiry dates, and status
- **Nameservers** -- authoritative NS records with resolved IPs, provider detection, and ASN info
- **DNS trace** -- the delegation path from root servers down to the authoritative nameserver
- **Records** -- A, AAAA, CNAME, MX, and TXT records with reverse DNS, provider identification, and ASN lookups

Provider detection is built in for 100+ DNS, hosting, CDN, and mail providers (Cloudflare, AWS, Google, Azure, Akamai, Fastly, etc.).

## Subdomain awareness

When given a subdomain, dnscrawler shows info for both the root domain and the subdomain:

```
$ dnscrawler www.example.co.uk
```

It handles multi-part TLDs (`.co.uk`, `.com.au`, `.kommune.no`, etc.) correctly.

## Install

```
go install github.com/auduny/dnscrawler@latest
```

Or build from source:

```
git clone https://github.com/auduny/dnscrawler.git
cd dnscrawler
go build
```

## Usage

```
dnscrawler <domain> [flags]
```

### Flags

| Flag | Description |
|------|-------------|
| `--no-whois` | Skip WHOIS lookup |
| `--no-trace` | Skip DNS trace |
| `-p, --provider` | Add custom provider pattern (`'regex:name'`) |

### Custom providers

Map nameserver hostnames to provider names with regex patterns:

```
dnscrawler example.com -p '\.mycompany\.com$:My Company'
```

Custom patterns take precedence over built-in ones. Multiple `-p` flags can be used.
