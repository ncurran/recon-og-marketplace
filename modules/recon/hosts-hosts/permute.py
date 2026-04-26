from recon.core.module import BaseModule
from recon.mixins.resolver import ResolverMixin
import dns.rdatatype
import dns.resolver


DEFAULT_WORDS = [
    'dev', 'test', 'staging', 'stage', 'prod', 'qa', 'uat',
    'api', 'admin', 'auth', 'beta', 'internal', 'mail', 'ftp', 'vpn',
]


class Module(BaseModule, ResolverMixin):

    meta = {
        'name': 'Hostname Permutation',
        'author': 'Nicholas Curran (@ncurran)',
        'version': '1.2',
        'description': (
            'Generates common permutations of known hostnames (dev-, staging-, '
            'api-, -2, etc.), resolves each via DNS, and inserts any that return '
            'an A record into the hosts table. Equivalent to altdns/alterx.'
        ),
        'comments': (
            'Uses the leftmost label of each host as the permutation seed.',
            'Patterns: insertion (word.host), prefix (word-leaf.rest), '
            'suffix (leaf-word.rest), and numeric suffix (leaf1, leaf2, leaf3).',
            'Only fans out from hosts whose root is in the domains table — '
            'CNAME targets recorded by brute_hosts (e.g. *.cdn.cloudflare.net, '
            '*.outlook.com) are skipped to avoid permuting vendor infrastructure '
            'into the workspace. Add such domains to the domains table to opt in.',
            'Records provenance chain on each insert (e.g. '
            '"alienvault.brute_hosts.permute") so it is traceable how each '
            'permuted host arrived in the workspace.',
        ),
        # Multi-column query: opt in to provenance tracking. Each input row
        # arrives as a (host, parent_module, parent_provenance) tuple; permute
        # extends the chain with its own name on insert.
        'query': 'SELECT DISTINCT host, module, provenance FROM hosts WHERE host IS NOT NULL',
        'accepts_provenance': True,
        'options': (
            ('words', ','.join(DEFAULT_WORDS), True, 'comma-separated permutation words'),
        ),
    }

    def module_run(self, hosts):
        words = [w.strip().lower() for w in self.options['words'].split(',') if w.strip()]
        resolver = self.get_resolver()
        seen = set()

        # Scope filter: only fan out from hosts under a known in-scope domain.
        # brute_hosts records CNAME targets as separate hosts (e.g. cloudflare,
        # akamai, outlook autodiscover) which are valid recon intel for
        # http_probe/takeover but must not become permutation seeds — that
        # multiplies vendor-infrastructure noise 30-40x via DNS fan-out.
        in_scope_rows = self.query(
            'SELECT domain FROM domains WHERE domain IS NOT NULL'
        ) or []
        in_scope = {
            (r[0].lower().rstrip('.') if r and r[0] else '')
            for r in in_scope_rows
        }
        in_scope.discard('')
        if not in_scope:
            # No domains seeded — fall back to the legacy "permute everything"
            # behaviour, but flag it loudly because the operator probably wants
            # the scope filter on.
            self.error(
                "Scope filter DISABLED: domains table is empty. Seed at least "
                "one domain (`db insert domains <root>~`) to prevent permute "
                "from fanning out off-domain CNAME targets recorded by "
                "brute_hosts (cloudflare, akamai, outlook, q4web, etc.)."
            )
        out_of_scope_skipped = 0

        for host_row in hosts:
            host, parent_chain = _unpack_provenance_row(host_row)
            host = host.lower()
            if '.' not in host:
                self.verbose(f"Skipping '{host}' (no subdomain to permute).")
                continue
            if in_scope and not _in_scope(host, in_scope):
                self.verbose(f"Skipping '{host}' (not under any in-scope domain).")
                out_of_scope_skipped += 1
                continue

            leaf, _, rest = host.partition('.')
            self.heading(host, level=0)

            # Compose this insert's provenance: extend the parent chain with
            # our own module name. If parent had no provenance recorded, this
            # is the chain root.
            new_chain = f"{parent_chain}.permute" if parent_chain else 'permute'

            candidates = self._candidates(leaf, rest, host, words)
            new_inserted = 0

            for candidate in candidates:
                if candidate in seen or candidate == host:
                    continue
                seen.add(candidate)

                try:
                    answers = resolver.query(candidate)
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    self.verbose(f'{candidate} => no record')
                    continue
                except (dns.resolver.NoNameservers, dns.resolver.Timeout):
                    self.verbose(f'{candidate} => DNS error')
                    continue

                for rdata in answers:
                    if rdata.rdtype == dns.rdatatype.A:
                        address = rdata.address
                        self.alert(f'{candidate} => {address}')
                        self.insert_hosts(host=candidate, ip_address=address,
                                          provenance=new_chain)
                        new_inserted += 1

            self.output(f"{new_inserted} new hosts from permutations of '{host}'.")

        if out_of_scope_skipped:
            self.output(
                f"Skipped {out_of_scope_skipped} host(s) outside of in-scope "
                f"domains (CNAME targets / vendor infra). Add those domains to "
                f"the domains table if you want them permuted."
            )

    @staticmethod
    def _candidates(leaf, rest, host, words):
        out = []
        # Insertion: word.host
        for word in words:
            out.append(f'{word}.{host}')
        # Prefix with dash: word-leaf.rest
        for word in words:
            out.append(f'{word}-{leaf}.{rest}')
        # Suffix with dash: leaf-word.rest
        for word in words:
            out.append(f'{leaf}-{word}.{rest}')
        # Numeric suffix
        for n in ('1', '2', '3'):
            out.append(f'{leaf}{n}.{rest}')
        return out


def _in_scope(host, in_scope_domains):
    """True iff host equals any in-scope domain or is a subdomain of one."""
    if not host or not in_scope_domains:
        return False
    h = host.lower().rstrip('.')
    for d in in_scope_domains:
        if h == d or h.endswith('.' + d):
            return True
    return False


def _unpack_provenance_row(row):
    """Normalise an input row that may be either:
    - a bare value string (no provenance available, e.g. file source), OR
    - a (value, parent_module, parent_provenance) tuple from a multi-column
      meta query opted into via 'accepts_provenance'.

    Returns (value, parent_chain) where parent_chain is the parent's
    provenance if present, else parent's module, else empty string."""
    if isinstance(row, (tuple, list)):
        value = row[0] if len(row) > 0 else ''
        parent_module = row[1] if len(row) > 1 else None
        parent_provenance = row[2] if len(row) > 2 else None
        return value, (parent_provenance or parent_module or '')
    return row, ''
