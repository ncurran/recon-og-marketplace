# recon-og-marketplace

Modules for [recon-og](https://github.com/ncurran/recon-og).

Modules are loaded from within the recon-og CLI. See the upstream [Development Guide](https://github.com/lanmaster53/recon-ng/wiki/Development-Guide) and [Wiki](https://github.com/lanmaster53/recon-ng/wiki) for the module API — most details carry over, though this fork may diverge over time.

---

## What's different from upstream

### New modules

| Module | Flow | Description |
|--------|------|-------------|
| `recon/domains-hosts/certspotter` | domains → hosts | Passive subdomain enumeration via the [Cert Spotter](https://sslmate.com/certspotter/) CT log API. Paginates through all certificates, extracts SANs, and inserts unique hostnames. Supports a `certspotter_api` key for higher rate limits. |
| `recon/domains-hosts/wayback` | domains → hosts | Extracts unique subdomains from the [Wayback Machine CDX API](https://web.archive.org/cdx/search) by querying all archived URLs under a domain. Free, no API key required. |
| `recon/companies-netblocks/asn_lookup` | companies → netblocks | Resolves company names to ASNs via the [HackerTarget ASN API](https://hackertarget.com/as-ip-lookup/), then fetches all announced CIDR prefixes (IPv4 and IPv6) and inserts them into the netblocks table. Filters to ASNs whose name shares a meaningful word with the company name. Supports a `hackertarget_api` key. Free tier: 50 requests/day. |

### Bug fixes (still open upstream)

| Module | Fix |
|--------|-----|
| `recon/companies-multi/whois_miner` | ARIN updated their "no results" response string; the old check no longer matched, causing the module to silently treat every lookup as a hit. Updated to match the current string. |
| `recon/domains-hosts/hackertarget` | `host, address = line.split(",")` crashes on lines with multiple commas. Fixed to `split(",", 1)` with a length guard. Also handles the `"API count exceeded"` body that HackerTarget returns as a 200 OK when the free-tier daily quota is hit — previously fell through into the parser and crashed. |

### Removed modules

| Module | Reason |
|--------|--------|
| `recon/domains-hosts/certificate_transparency` | Replaced by `certspotter`. The crt.sh backend is rate-limited and returns inconsistent results; Cert Spotter's paginated API is more reliable. |

### Test suite

`test_modules.py` at the repo root runs all module tests without a live recon-og installation. The framework is stubbed out so tests run fast and offline.

```
python3 test_modules.py
```

Currently 113 tests covering every module in this repo.

---

## Planned modules


| Module | Flow | What it does |
|--------|------|-------------|
| `recon/hosts-hosts/permute` | hosts → hosts | Hostname permutation (dev-, staging-, api-, -2, etc.) + DNS resolution. |
| `recon/hosts-vulnerabilities/takeover` | hosts → vulnerabilities | CNAME chain walking + fingerprint against known-vulnerable services. |
| `recon/hosts-ports/http_probe` | hosts → ports | Fast HTTP/HTTPS alive check — status, title, server header. |
</content>
</invoke>