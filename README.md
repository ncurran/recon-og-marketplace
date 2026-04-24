# recon-og-marketplace

Modules for [recon-og](https://github.com/ncurran/recon-og).

Modules are loaded from within the recon-og CLI. See the upstream [Development Guide](https://github.com/lanmaster53/recon-ng/wiki/Development-Guide) and [Wiki](https://github.com/lanmaster53/recon-ng/wiki) for the module API — most details carry over, though this fork may diverge over time.

---

## What's different from upstream

### New modules

| Module | Flow | Description |
|--------|------|-------------|
| `recon/domains-hosts/alienvault` | domains → hosts | Passive subdomain enumeration via the [AlienVault OTX](https://otx.alienvault.com) `url_list` endpoint. Free, no API key required. Paginates automatically; extracts unique hostnames from each observed URL. |
| `recon/domains-hosts/certspotter` | domains → hosts | Passive subdomain enumeration via the [Cert Spotter](https://sslmate.com/certspotter/) CT log API. Paginates through all certificates, extracts SANs, and inserts unique hostnames. Supports a `certspotter_api` key for higher rate limits. |
| `recon/domains-hosts/wayback` | domains → hosts | Extracts unique subdomains from the [Wayback Machine CDX API](https://web.archive.org/cdx/search) by querying all archived URLs under a domain. Free, no API key required. |
| `recon/companies-netblocks/asn_lookup` | companies → netblocks | Resolves company names to ASNs via the [HackerTarget ASN API](https://hackertarget.com/as-ip-lookup/), then fetches all announced CIDR prefixes (IPv4 and IPv6) and inserts them into the netblocks table. Filters to ASNs whose name shares a meaningful word with the company name. Supports a `hackertarget_api` key. Free tier: 50 requests/day. |
| `recon/hosts-hosts/permute` | hosts → hosts | Generates common hostname permutations (insertion like `dev.api.example.com`, prefix/suffix with dash, numeric suffix) and resolves each via DNS. Inserts any that return an A record. Equivalent to altdns/alterx. Wordlist configurable via the `words` option. |

### Bug fixes (still open upstream)

| Module | Fix |
|--------|-----|
| `recon/companies-multi/whois_miner` | ARIN updated their "no results" response string; the old check no longer matched, causing the module to silently treat every lookup as a hit. Updated to match the current string. |
| `recon/domains-hosts/hackertarget` | `host, address = line.split(",")` crashes on lines with multiple commas. Fixed to `split(",", 1)` with a length guard. Also handles the `"API count exceeded"` body that HackerTarget returns as a 200 OK when the free-tier daily quota is hit — previously fell through into the parser and crashed. |
| `recon/companies-domains/censys_subdomains` | Import of `CensysCertificates` failed because the symbol was renamed to `CensysCerts` in `censys>=2.x`. Module was disabled on every startup. Updated import, constructor kwargs, and v2 `.search()` pagination signature. |
| `recon/domains-contacts/metacrawler` | Depended on `PyPDF3` which is abandoned and no longer installable. Migrated to the actively maintained `pypdf` (`PdfFileReader` → `PdfReader`, `isEncrypted` → `is_encrypted`, `getDocumentInfo()` → `metadata`). Module was disabled on every startup. |
| `recon/companies-contacts/bing_linkedin_cache`, `recon/domains-contacts/wikileaker`, `recon/contacts-contacts/mangle` | Regex strings contained unescaped backslashes (`'\d'`, `'\.'`, `'\s'`) in non-raw string literals. Emitted `SyntaxWarning` on every import under Python 3.12+ and will become `SyntaxError` in a future Python release. Converted to raw strings. |

### Removed modules

| Module | Reason |
|--------|--------|
| `recon/domains-hosts/certificate_transparency` | Replaced by `certspotter`. The crt.sh backend is rate-limited and returns inconsistent results; Cert Spotter's paginated API is more reliable. |
| `recon/credentials-credentials/adobe` | Backend resource (`stricture-group.com/files/adobe-top100.txt`) now 302-redirects to the homepage — the 2013 Adobe-breach hash list is no longer served. Module also uses Python 2 `str.decode('base64')` and has never worked under Python 3. `hibp_breach` and `hibp_paste` cover the Adobe breach plus every other major breach in HIBP's canonical DB. |
| `recon/profiles-profiles/namechk` | The module called `api.namechk.com`, whose DNS no longer resolves (`curl: (6) Could not resolve host`). The public web UI at `namechk.com` is still up but sits behind a Cloudflare JS challenge (HTTP 403 on any programmatic access). `profiler` (WhatsMyName-backed) covers the same username-check-on-many-sites capability with a broader, maintained site list. |
| `recon/domains-vulnerabilities/xssed` | `xssed.com` search still responds but individual mirror detail pages return HTTP 500 — result IDs come back but nothing can be fetched from them. Site has also not added new data since ~2013. No modern equivalent with an open API (OpenBugBounty, the closest candidate, is Cloudflare-gated). |

### Test suite

`test_modules.py` at the repo root runs all module tests without a live recon-og installation. The framework is stubbed out so tests run fast and offline.

```
python3 test_modules.py
```

Currently 140 tests covering every module in this repo, including `TestModuleHealth` which fails if any module emits a `SyntaxWarning` at compile or fails to import.
