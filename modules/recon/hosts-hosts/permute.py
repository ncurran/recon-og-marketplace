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
        'version': '1.0',
        'description': (
            'Generates common permutations of known hostnames (dev-, staging-, '
            'api-, -2, etc.), resolves each via DNS, and inserts any that return '
            'an A record into the hosts table. Equivalent to altdns/alterx.'
        ),
        'comments': (
            'Uses the leftmost label of each host as the permutation seed.',
            'Patterns: insertion (word.host), prefix (word-leaf.rest), '
            'suffix (leaf-word.rest), and numeric suffix (leaf1, leaf2, leaf3).',
        ),
        'query': 'SELECT DISTINCT host FROM hosts WHERE host IS NOT NULL',
        'options': (
            ('words', ','.join(DEFAULT_WORDS), True, 'comma-separated permutation words'),
        ),
    }

    def module_run(self, hosts):
        words = [w.strip().lower() for w in self.options['words'].split(',') if w.strip()]
        resolver = self.get_resolver()
        seen = set()

        for host in hosts:
            host = host.lower()
            if '.' not in host:
                self.verbose(f"Skipping '{host}' (no subdomain to permute).")
                continue

            leaf, _, rest = host.partition('.')
            self.heading(host, level=0)

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
                        self.insert_hosts(host=candidate, ip_address=address)
                        new_inserted += 1

            self.output(f"{new_inserted} new hosts from permutations of '{host}'.")

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
