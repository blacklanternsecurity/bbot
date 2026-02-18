from bbot.modules.templates.censys import censys


class censys_ip(censys):
    """
    Query the Censys /v2/hosts/{ip} endpoint for associated hostnames, IPs, and URLs.
    """

    watched_events = ["IP_ADDRESS"]
    produced_events = [
        "IP_ADDRESS",
        "DNS_NAME",
        "URL_UNVERIFIED",
        "OPEN_TCP_PORT",
        "OPEN_UDP_PORT",
        "TECHNOLOGY",
        "PROTOCOL",
    ]
    flags = ["passive", "safe"]
    meta = {
        "description": "Query the Censys API for hosts by IP address",
        "created_date": "2026-01-26",
        "author": "@TheTechromancer",
        "auth_required": True,
    }
    options = {"api_key": "", "dns_names_limit": 100, "in_scope_only": True}
    options_desc = {
        "api_key": "Censys.io API Key in the format of 'key:secret'",
        "dns_names_limit": "Maximum number of DNS names to extract from dns.names (default 100)",
        "in_scope_only": "Only query in-scope IPs. If False, will query up to distance 1.",
    }
    scope_distance_modifier = 1

    async def setup(self):
        self.dns_names_limit = self.config.get("dns_names_limit", 100)
        self.warning(
            "This module may consume a lot of API queries. Unless you specifically want to query on each individual IP, we recommend using the censys_dns module instead."
        )
        return await super().setup()

    async def filter_event(self, event):
        in_scope_only = self.config.get("in_scope_only", True)
        max_scope_distance = 0 if in_scope_only else (self.scan.scope_search_distance + 1)
        if event.scope_distance > max_scope_distance:
            return False, "event is not in scope"
        return True

    async def handle_event(self, event):
        ip = str(event.host)
        url = f"{self.base_url}/v2/hosts/{ip}"

        resp = await self.api_request(url)
        if resp is None:
            self.debug(f"No response for {ip}")
            return

        if resp.status_code == 404:
            self.debug(f"No data found for {ip}")
            return

        if resp.status_code != 200:
            self.verbose(f"Non-200 status code ({resp.status_code}) for {ip}")
            return

        try:
            data = resp.json()
        except Exception as e:
            self.warning(f"Failed to parse JSON response for {ip}: {e}")
            return

        result = data.get("result", {})
        if not result:
            return

        # Track what we've already emitted to avoid duplicates
        seen = set()

        # Extract data from services
        for service in result.get("services", []):
            port = service.get("port")
            transport = service.get("transport_protocol", "TCP").upper()

            # Emit OPEN_TCP_PORT or OPEN_UDP_PORT for services with a port
            # QUIC uses UDP as transport, so treat it as UDP
            if port and (port, transport) not in seen:
                seen.add((port, transport))
                if transport in ("UDP", "QUIC"):
                    event_type = "OPEN_UDP_PORT"
                else:
                    event_type = "OPEN_TCP_PORT"
                await self.emit_event(
                    self.helpers.make_netloc(ip, port),
                    event_type,
                    parent=event,
                    context="{module} found open port on {event.parent.data}",
                )

            # Emit PROTOCOL for non-HTTP services
            # Use extended_service_name (more specific) falling back to service_name
            # Also check transport_protocol for protocols like QUIC
            service_name = service.get("extended_service_name") or service.get("service_name", "")
            # If service_name is UNKNOWN but transport_protocol is meaningful, use that
            if service_name.upper() == "UNKNOWN" and transport and transport not in ("TCP", "UDP"):
                service_name = transport
            if service_name and service_name.upper() not in ("HTTP", "HTTPS", "UNKNOWN"):
                protocol_key = ("protocol", service_name.upper(), port)
                if protocol_key not in seen:
                    seen.add(protocol_key)
                    protocol_data = {"host": str(event.host), "protocol": service_name}
                    if port:
                        protocol_data["port"] = port
                    await self.emit_event(
                        protocol_data,
                        "PROTOCOL",
                        parent=event,
                        context="{module} found {event.type}: {event.data[protocol]} on {event.parent.data}",
                    )

            # Extract URLs from HTTP services
            http_data = service.get("http", {})
            request = http_data.get("request", {})
            uri = request.get("uri")
            if uri and uri not in seen:
                seen.add(uri)
                await self.emit_event(
                    uri,
                    "URL_UNVERIFIED",
                    parent=event,
                    context="{module} found {event.data} in HTTP service of {event.parent.data}",
                )

            # Extract TLS certificate data
            tls_data = service.get("tls", {})
            certs = tls_data.get("certificates", {})
            leaf_data = certs.get("leaf_data", {})

            # Extract names from leaf_data.names
            for name in leaf_data.get("names", []):
                await self._emit_host(name, event, seen, "TLS certificate")

            # Extract common_name from leaf_data.subject
            subject = leaf_data.get("subject", {})
            for cn in subject.get("common_name", []):
                await self._emit_host(cn, event, seen, "TLS certificate subject")

            # Extract software/technologies
            for software in service.get("software", []):
                product = software.get("uniform_resource_identifier", software.get("product", ""))
                if product:
                    await self.emit_event(
                        {"technology": product, "host": str(event.host)},
                        "TECHNOLOGY",
                        parent=event,
                        context="{module} found {event.type}: {event.data[technology]} on {event.parent.data}",
                    )

        # Extract dns.names (limit to configured max)
        dns_data = result.get("dns", {})
        dns_names = dns_data.get("names", [])
        for name in dns_names[: self.dns_names_limit]:
            await self._emit_host(name, event, seen, "reverse DNS")

    async def _emit_host(self, host, event, seen, source):
        """Emit IP_ADDRESS or DNS_NAME for a host value."""
        # Validate and emit as DNS_NAME
        try:
            validated = self.helpers.validators.validate_host(host)
        except ValueError as e:
            self.debug(f"Error validating host {host} in {source}: {e}")
        if validated and validated not in seen:
            seen.add(validated)
            await self.emit_event(
                validated,
                "DNS_NAME",
                parent=event,
                context=f"{{module}} found {{event.data}} in {source} of {{event.parent.data}}",
            )
