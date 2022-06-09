from .crobat import crobat


class dnsgrep(crobat):
    def query(self, query):
        results = self.helpers.request(f"https://dns.bufferover.run/dns?q={query}")
        try:
            json = results.json()
            if json:
                for entry in json["FDNS_A"]:
                    try:
                        ip, hostname = entry.split(",")
                    except ValueError:
                        continue
                    yield hostname
            else:
                self.debug(f'No results for "{query}"')
        except Exception:
            import traceback

            self.warning(f"Error retrieving dnsgrep domains")
            self.debug(traceback.format_exc())
