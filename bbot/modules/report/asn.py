from bbot.core.errors import ScanCancelledError
from bbot.modules.report.base import BaseReportModule


class asn(BaseReportModule):
    watched_events = ["IP_ADDRESS"]
    produced_events = ["ASN"]
    flags = ["passive", "subdomain-enum", "safe"]
    meta = {"description": "Query ripe and bgpview.io for ASNs"}
    scope_distance_modifier = 0

    def setup(self):
        self.asn_counts = {}
        self.asn_cache = {}
        self.sources = ["bgpview", "ripe"]
        self.unknown_asn = {
            "asn": "UNKNOWN",
            "subnet": "0.0.0.0/32",
            "name": "unknown",
            "description": "unknown",
            "country": "",
        }
        return True

    def filter_event(self, event):
        if getattr(event.host, "is_private", False):
            return False
        return True

    def handle_event(self, event):
        host = event.host
        if self.cache_get(host) == False:
            asns = list(self.get_asn(host))
            if not asns:
                self.cache_put(self.unknown_asn)
            else:
                for asn in asns:
                    emails = asn.pop("emails", [])
                    self.cache_put(asn)
                    asn_event = self.make_event(asn, "ASN", source=event)
                    self.emit_event(asn_event)
                    for email in emails:
                        self.emit_event(email, "EMAIL_ADDRESS", source=asn_event)

    def report(self):
        asn_data = sorted(self.asn_cache.items(), key=lambda x: self.asn_counts[x[0]], reverse=True)
        if not asn_data:
            return
        header = ["ASN", "Subnet", "Host Count", "Name", "Description", "Country"]
        table = []
        for subnet, asn in asn_data:
            count = self.asn_counts[subnet]
            number = asn["asn"]
            if number != "UNKNOWN":
                number = "AS" + number
            name = asn["name"]
            country = asn["country"]
            description = asn["description"]
            table.append([number, str(subnet), f"{count:,}", name, description, country])
        for row in self.helpers.make_table(table, header).splitlines():
            self.info(row)

    def cache_put(self, asn):
        asn = dict(asn)
        subnet = self.helpers.make_ip_type(asn.pop("subnet"))
        self.asn_cache[subnet] = asn
        try:
            self.asn_counts[subnet] += 1
        except KeyError:
            self.asn_counts[subnet] = 1

    def cache_get(self, ip):
        ret = False
        for p in self.helpers.ip_network_parents(ip):
            try:
                self.asn_counts[p] += 1
                if ret == False:
                    ret = p
            except KeyError:
                continue
        return ret

    def get_asn(self, ip, retries=1):
        """
        Takes in an IP
        returns a list of ASNs, e.g.:
            [{'asn': '54113', 'subnet': '2606:50c0:8000::/48', 'name': 'FASTLY', 'description': 'Fastly', 'country': 'US', 'emails': []}, {'asn': '54113', 'subnet': '2606:50c0:8000::/46', 'name': 'FASTLY', 'description': 'Fastly', 'country': 'US', 'emails': []}]
        """
        for attempt in range(retries + 1):
            for i, source in enumerate(list(self.sources)):
                if self.scan.stopping:
                    raise ScanCancelledError()
                get_asn_fn = getattr(self, f"get_asn_{source}")
                res = get_asn_fn(ip)
                if res == False:
                    # demote the current source to lowest priority since it just failed
                    self.sources.append(self.sources.pop(i))
                    self.verbose(f"Failed to contact {source}, retrying")
                    continue
                return res
        self.warning(f"Error retrieving ASN via for {ip}")
        return []

    def get_asn_ripe(self, ip):
        url = f"https://stat.ripe.net/data/network-info/data.json?resource={ip}"
        response = self.get_url(url, "ASN")
        asns = []
        if response == False:
            return False
        data = response.get("data", {})
        if not data:
            data = {}
        prefix = data.get("prefix", "")
        asn_numbers = data.get("asns", [])
        if not prefix or not asn_numbers:
            return []
        if not asn_numbers:
            asn_numbers = []
        for number in asn_numbers:
            asn = self.get_asn_metadata_ripe(number)
            asn["subnet"] = prefix
            asns.append(asn)
        return asns

    def get_asn_metadata_ripe(self, asn_number):
        metadata_keys = {
            "name": ["ASName", "OrgId"],
            "description": ["OrgName", "OrgTechName", "RTechName"],
            "country": ["Country"],
        }
        url = f"https://stat.ripe.net/data/whois/data.json?resource={asn_number}"
        response = self.get_url(url, "ASN Metadata", cache=True)
        if response == False:
            return False
        data = response.get("data", {})
        if not data:
            data = {}
        records = data.get("records", [])
        if not records:
            records = []
        emails = set()
        asn = {k: "" for k in metadata_keys.keys()}
        for record in records:
            for item in record:
                key = item.get("key", "")
                value = item.get("value", "")
                for email in self.helpers.extract_emails(value):
                    emails.add(email.lower())
                if not key:
                    continue
                if value:
                    for keyname, keyvals in metadata_keys.items():
                        if key in keyvals and not asn.get(keyname, ""):
                            asn[keyname] = value
        asn["emails"] = list(emails)
        asn["asn"] = str(asn_number)
        return asn

    def get_asn_bgpview(self, ip):
        url = f"https://api.bgpview.io/ip/{ip}"
        data = self.get_url(url, "ASN")
        asns = []
        asns_tried = set()
        if data == False:
            return False
        data = data.get("data", {})
        prefixes = data.get("prefixes", [])
        for prefix in prefixes:
            details = prefix.get("asn", {})
            asn = str(details.get("asn", ""))
            subnet = prefix.get("prefix", "")
            if not (asn or subnet):
                continue
            name = details.get("name") or prefix.get("name") or ""
            description = details.get("description") or prefix.get("description") or ""
            country = details.get("country_code") or prefix.get("country_code") or ""
            emails = []
            if not asn in asns_tried:
                emails = self.get_emails_bgpview(asn)
                if emails == False:
                    return False
                asns_tried.add(asn)
            asns.append(
                dict(asn=asn, subnet=subnet, name=name, description=description, country=country, emails=emails)
            )
        if not asns:
            self.debug(f'No results for "{ip}"')
        return asns

    def get_emails_bgpview(self, asn):
        contacts = []
        url = f"https://api.bgpview.io/asn/{asn}"
        data = self.get_url(url, "ASN metadata", cache=True)
        if data == False:
            return False
        data = data.get("data", {})
        if not data:
            self.debug(f'No results for "{asn}"')
            return
        email_contacts = data.get("email_contacts", [])
        abuse_contacts = data.get("abuse_contacts", [])
        contacts = [l.strip().lower() for l in email_contacts + abuse_contacts]
        return list(set(contacts))

    def get_url(self, url, data_type, cache=False):
        kwargs = {}
        if cache:
            kwargs["cache_for"] = 60 * 60 * 24
        r = self.helpers.request(url, **kwargs)
        data = {}
        try:
            j = r.json()
            if not isinstance(j, dict):
                return data
            return j
        except Exception as e:
            self.verbose(f"Error retrieving {data_type} at {url}: {e}")
            self.debug(f"Got data: {getattr(r, 'content', '')}")
            return False
