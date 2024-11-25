from bbot.modules.report.base import BaseReportModule


class asn(BaseReportModule):
    watched_events = ["IP_ADDRESS"]
    produced_events = ["ASN"]
    flags = ["passive", "subdomain-enum", "safe"]
    meta = {
        "description": "Query ripe and bgpview.io for ASNs",
        "created_date": "2022-07-25",
        "author": "@TheTechromancer",
    }
    scope_distance_modifier = 1
    # we accept dupes to avoid missing data
    # because sometimes IP addresses are re-emitted with lower scope distances
    accept_dupes = True

    async def setup(self):
        self.asn_counts = {}
        self.asn_cache = {}
        self.ripe_cache = {}
        self.sources = ["bgpview", "ripe"]
        self.unknown_asn = {
            "asn": "UNKNOWN",
            "subnet": "0.0.0.0/32",
            "name": "unknown",
            "description": "unknown",
            "country": "",
        }
        return True

    async def filter_event(self, event):
        if str(event.module) == "ipneighbor":
            return False
        if getattr(event.host, "is_private", False):
            return False
        return True

    async def handle_event(self, event):
        host = event.host
        if self.cache_get(host) is False:
            asns, source = await self.get_asn(host)
            if not asns:
                self.cache_put(self.unknown_asn)
            else:
                for asn in asns:
                    emails = asn.pop("emails", [])
                    self.cache_put(asn)
                    asn_event = self.make_event(asn, "ASN", parent=event)
                    asn_number = asn.get("asn", "")
                    asn_desc = asn.get("description", "")
                    asn_name = asn.get("name", "")
                    asn_subnet = asn.get("subnet", "")
                    if not asn_event:
                        continue
                    await self.emit_event(
                        asn_event,
                        context=f"{{module}} checked {event.data} against {source} API and got {{event.type}}: AS{asn_number} ({asn_name}, {asn_desc}, {asn_subnet})",
                    )
                    for email in emails:
                        await self.emit_event(
                            email,
                            "EMAIL_ADDRESS",
                            parent=asn_event,
                            context=f"{{module}} retrieved details for AS{asn_number} and found {{event.type}}: {{event.data}}",
                        )

    async def report(self):
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
        self.log_table(table, header, table_name="asns")

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
                if ret is False:
                    ret = p
            except KeyError:
                continue
        return ret

    async def get_asn(self, ip, retries=1):
        """
        Takes in an IP
        returns a list of ASNs, e.g.:
            [{'asn': '54113', 'subnet': '2606:50c0:8000::/48', 'name': 'FASTLY', 'description': 'Fastly', 'country': 'US', 'emails': []}, {'asn': '54113', 'subnet': '2606:50c0:8000::/46', 'name': 'FASTLY', 'description': 'Fastly', 'country': 'US', 'emails': []}]
        """
        for attempt in range(retries + 1):
            for i, source in enumerate(list(self.sources)):
                get_asn_fn = getattr(self, f"get_asn_{source}")
                res = await get_asn_fn(ip)
                if res is False:
                    # demote the current source to lowest priority since it just failed
                    self.sources.append(self.sources.pop(i))
                    self.verbose(f"Failed to contact {source}, retrying")
                    continue
                return res, source
        self.warning(f"Error retrieving ASN for {ip}")
        return [], ""

    async def get_asn_ripe(self, ip):
        url = f"https://stat.ripe.net/data/network-info/data.json?resource={ip}"
        response = await self.get_url(url, "ASN")
        asns = []
        if response is False:
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
            asn = await self.get_asn_metadata_ripe(number)
            if asn is False:
                return False
            asn["subnet"] = prefix
            asns.append(asn)
        return asns

    async def get_asn_metadata_ripe(self, asn_number):
        try:
            return self.ripe_cache[asn_number]
        except KeyError:
            metadata_keys = {
                "name": ["ASName", "OrgId"],
                "description": ["OrgName", "OrgTechName", "RTechName"],
                "country": ["Country"],
            }
            url = f"https://stat.ripe.net/data/whois/data.json?resource={asn_number}"
            response = await self.get_url(url, "ASN Metadata", cache=True)
            if response is False:
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
                    for email in await self.helpers.re.extract_emails(value):
                        emails.add(email.lower())
                    if not key:
                        continue
                    if value:
                        for keyname, keyvals in metadata_keys.items():
                            if key in keyvals and not asn.get(keyname, ""):
                                asn[keyname] = value
            asn["emails"] = list(emails)
            asn["asn"] = str(asn_number)
            self.ripe_cache[asn_number] = asn
            return asn

    async def get_asn_bgpview(self, ip):
        url = f"https://api.bgpview.io/ip/{ip}"
        data = await self.get_url(url, "ASN")
        asns = []
        asns_tried = set()
        if data is False:
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
            if asn not in asns_tried:
                emails = await self.get_emails_bgpview(asn)
                if emails is False:
                    return False
                asns_tried.add(asn)
            asns.append(
                {
                    "asn": asn,
                    "subnet": subnet,
                    "name": name,
                    "description": description,
                    "country": country,
                    "emails": emails,
                }
            )
        if not asns:
            self.debug(f'No results for "{ip}"')
        return asns

    async def get_emails_bgpview(self, asn):
        contacts = []
        url = f"https://api.bgpview.io/asn/{asn}"
        data = await self.get_url(url, "ASN metadata", cache=True)
        if data is False:
            return False
        data = data.get("data", {})
        if not data:
            self.debug(f'No results for "{asn}"')
            return
        email_contacts = data.get("email_contacts", [])
        abuse_contacts = data.get("abuse_contacts", [])
        contacts = [l.strip().lower() for l in email_contacts + abuse_contacts]
        return list(set(contacts))

    async def get_url(self, url, data_type, cache=False):
        kwargs = {}
        if cache:
            kwargs["cache_for"] = 60 * 60 * 24
        r = await self.helpers.request(url, **kwargs)
        data = {}
        try:
            j = r.json()
            if not isinstance(j, dict):
                return data
            return j
        except Exception as e:
            self.verbose(f"Error retrieving {data_type} at {url}: {e}", trace=True)
            self.debug(f"Got data: {getattr(r, 'content', '')}")
            return False
