from recon.core.module import BaseModule
from recon.mixins.resolver import ResolverMixin
from recon.mixins.threads import ThreadingMixin
import dns.resolver
import os

class Module(BaseModule, ResolverMixin, ThreadingMixin):

    meta = {
        'name': 'DNS Hostname Brute Forcer',
        'author': 'Tim Tomes (@lanmaster53); provenance opt-in by Nicholas Curran',
        'version': '1.1',
        'description': 'Brute forces host names using DNS. Updates the \'hosts\' table with the results. Records provenance chain on each insert (e.g. "alienvault.brute_hosts") so it is traceable how each discovered host arrived.',
        # Multi-column query: opt into provenance tracking. Each input row
        # arrives as a (domain, parent_module, parent_provenance) tuple.
        'query': 'SELECT DISTINCT domain, module, provenance FROM domains WHERE domain IS NOT NULL',
        'accepts_provenance': True,
        'options': (
            ('wordlist', os.path.join(BaseModule.data_path, 'hostnames.txt'), True, 'path to hostname wordlist'),
        ),
        'files': ['hostnames.txt'],
    }

    def module_run(self, domains):
        with open(self.options['wordlist']) as fp:
            words = fp.read().split()
        resolver = self.get_resolver()
        for domain_row in domains:
            domain, parent_chain = _unpack_provenance_row(domain_row)
            self.heading(domain, level=0)
            wildcard = None
            try:
                answers = resolver.query(f"*.{domain}")
                wildcard = answers.response.answer[0][0]
                self.output(f"Wildcard DNS entry found for '{domain}' at '{wildcard}'.")
            except (dns.resolver.NoNameservers, dns.resolver.Timeout):
                self.error('Invalid nameserver.')
                continue
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                self.verbose('No Wildcard DNS entry found.')
            new_chain = f"{parent_chain}.brute_hosts" if parent_chain else 'brute_hosts'
            self.thread(words, domain, resolver, wildcard, new_chain)

    def module_thread(self, word, domain, resolver, wildcard, provenance):
        max_attempts = 3
        attempt = 0
        while attempt < max_attempts:
            host = f"{word}.{domain}"
            try:
                answers = resolver.query(host)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                self.verbose(f"{host} => No record found.")
            except dns.resolver.Timeout:
                self.verbose(f"{host} => Request timed out.")
                attempt += 1
                continue
            else:
                # process answers
                if answers.response.answer[0][0] == wildcard:
                    self.verbose(f"{host} => Response matches the wildcard.")
                else:
                    for answer in answers.response.answer:
                        for rdata in answer:
                            if rdata.rdtype in (1, 5):
                                if rdata.rdtype == 1:
                                    address = rdata.address
                                    self.alert(f"{host} => (A) {address}")
                                    self.insert_hosts(host=host, ip_address=address,
                                                      provenance=provenance)
                                if rdata.rdtype == 5:
                                    cname = rdata.target.to_text()[:-1]
                                    self.alert(f"{host} => (CNAME) {cname}")
                                    self.insert_hosts(host=cname, provenance=provenance)
                                    # add the host in case a CNAME exists without an A record
                                    self.insert_hosts(host=host, provenance=provenance)
            # break out of the loop
            attempt = max_attempts


def _unpack_provenance_row(row):
    """Normalise an input row that may be a bare string or a
    (value, parent_module, parent_provenance) tuple. Returns
    (value, parent_chain) where parent_chain is the parent's provenance
    if present, else its module, else an empty string. Mirrors permute's
    helper — both pilot modules use the same shape."""
    if isinstance(row, (tuple, list)):
        value = row[0] if len(row) > 0 else ''
        parent_module = row[1] if len(row) > 1 else None
        parent_provenance = row[2] if len(row) > 2 else None
        return value, (parent_provenance or parent_module or '')
    return row, ''
