from recon.core.module import BaseModule


class Module(BaseModule):

    meta = {
        'name': 'Certspotter Certificate Transparency',
        'author': 'Nicholas Curran',
        'version': '1.0',
        'description': (
            'Searches certificate transparency data via the SSLMate Certspotter '
            'API, adding newly identified hosts to the hosts table. '
            'Paginates automatically until all issuances are retrieved.'
        ),
        'comments': (
            'No API key required (free tier: 10 include_subdomains queries/hour).',
            'Set the certspotter_api key to increase rate limits.',
        ),
        'query': 'SELECT DISTINCT domain FROM domains WHERE domain IS NOT NULL',
    }

    def module_run(self, domains):
        for domain in domains:
            self.heading(domain, level=0)
            after = None
            while True:
                params = {
                    'domain': domain,
                    'include_subdomains': 'true',
                    'expand': 'dns_names',
                }
                if after:
                    params['after'] = after

                resp = self.request(
                    'GET',
                    'https://api.certspotter.com/v1/issuances',
                    params=params,
                )

                if resp.status_code == 429:
                    self.error(f"Rate limit reached for '{domain}'.")
                    break
                if resp.status_code != 200:
                    self.error(f"Unexpected response for '{domain}': {resp.status_code}")
                    break

                certs = resp.json()
                if not certs:
                    break

                for cert in certs:
                    for host in cert.get('dns_names') or []:
                        if '@' in host:
                            self.insert_contacts(email=host)
                            self.insert_hosts(host.split('@')[1])
                        else:
                            self.insert_hosts(host)

                after = certs[-1]['id']
