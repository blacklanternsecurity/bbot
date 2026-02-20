from contextlib import suppress

from bbot.modules.templates.subdomain_enum import subdomain_enum


class leaklookup(subdomain_enum):
    watched_events = ["DNS_NAME", "HASHED_PASSWORD"]
    produced_events = ["EMAIL_ADDRESS", "HASHED_PASSWORD", "PASSWORD", "USERNAME"]
    flags = ["passive", "safe", "email-enum"]
    meta = {
        "description": "Query leak-lookup.com for leaked credentials and crack hashes",
        "created_date": "2026-02-19",
        "author": "@carlospolop",
        "auth_required": True,
    }
    options = {"api_key": ""}
    options_desc = {"api_key": "Leak-Lookup API key"}

    search_url = "https://leak-lookup.com/api/search"
    hash_url = "https://leak-lookup.com/api/hash"

    email_fields = {
        "email_address",
        "emailaddress",
        "email",
        "email_address2",
        "emailaddress2",
        "email2",
    }
    username_fields = {"membername", "username", "uname", "user_name", "member_name"}
    password_fields = {"password", "password2", "password3", "password4", "plaintext", "secret", "key"}
    hashed_password_fields = {"hash"}

    async def setup(self):
        self.api_key = self.config.get("api_key", "")
        if not self.api_key:
            return None, "No API key set"
        return await super().setup()

    def _incoming_dedup_hash(self, event):
        if event.type == "DNS_NAME":
            return hash(self.make_query(event)), "dedup_strategy=highest_parent"
        if event.type == "HASHED_PASSWORD":
            _, hash_value = self._split_hashed_password_event(event)
            return hash(hash_value), "dedup_strategy=hash_value"
        return super()._incoming_dedup_hash(event)

    def make_query(self, event):
        if event.type != "DNS_NAME":
            return event.data
        return super().make_query(event)

    async def handle_event(self, event):
        if event.type == "DNS_NAME":
            await self.handle_dns_name_event(event)
        elif event.type == "HASHED_PASSWORD":
            await self.handle_hashed_password_event(event)

    async def handle_dns_name_event(self, event):
        query = self.make_query(event)
        response = await self.helpers.request(
            self.search_url,
            method="POST",
            data={"key": self.api_key, "type": "domain", "query": query},
        )
        json_result = self._safe_json(response)
        if not json_result:
            return
        if str(json_result.get("error", "")).lower() == "true":
            message = json_result.get("message", "")
            self.warning(f'Leak-Lookup returned an error for "{query}": {message}')
            return
        raw_results = json_result.get("message", {})
        if not isinstance(raw_results, dict):
            self.debug(f'No valid results returned from Leak-Lookup for "{query}"')
            return
        for source, source_rows in raw_results.items():
            if not isinstance(source_rows, list):
                continue
            source_tag = f"leaklookup-source-{self.helpers.tagify(source, maxlen=48)}"
            for row in source_rows:
                if isinstance(row, dict):
                    await self._emit_row_results(row, event, query, source_tag)

    async def _emit_row_results(self, row, parent_event, query, source_tag):
        emails = await self._extract_emails_from_row(row)
        usernames = self._extract_values_by_fields(row, self.username_fields)
        passwords = self._extract_values_by_fields(row, self.password_fields)
        hashed_passwords = self._extract_values_by_fields(row, self.hashed_password_fields)

        for email in emails:
            email_event = self.make_event(email, "EMAIL_ADDRESS", parent=parent_event, tags=[source_tag])
            if email_event is None:
                continue
            await self.emit_event(
                email_event,
                context=f'{{module}} searched Leak-Lookup for "{query}" and found {{event.type}}: {{event.data}}',
            )
            for username in usernames:
                await self.emit_event(
                    f"{email}:{username}",
                    "USERNAME",
                    parent=email_event,
                    tags=[source_tag],
                    context=f"{{module}} found {email} with {{event.type}}: {{event.data}}",
                )
            for password in passwords:
                await self.emit_event(
                    f"{email}:{password}",
                    "PASSWORD",
                    parent=email_event,
                    tags=[source_tag],
                    context=f"{{module}} found {email} with {{event.type}}: {{event.data}}",
                )
            for hashed_password in hashed_passwords:
                await self.emit_event(
                    f"{email}:{hashed_password}",
                    "HASHED_PASSWORD",
                    parent=email_event,
                    tags=[source_tag],
                    context=f"{{module}} found {email} with {{event.type}}: {{event.data}}",
                )

    async def handle_hashed_password_event(self, event):
        identity, hash_value = self._split_hashed_password_event(event)
        if not hash_value:
            return

        response = await self.helpers.request(
            self.hash_url,
            method="POST",
            data={"key": self.api_key, "query": hash_value},
        )
        json_result = self._safe_json(response)
        if not json_result:
            return
        if str(json_result.get("error", "")).lower() == "true":
            message = json_result.get("message", "")
            self.warning(f'Leak-Lookup hash lookup failed for "{hash_value}": {message}')
            return

        message = json_result.get("message", {})
        if not isinstance(message, dict):
            return

        for source_rows in message.values():
            if not isinstance(source_rows, list):
                continue
            for row in source_rows:
                if not isinstance(row, dict):
                    continue
                plaintext = str(row.get("plaintext", "")).strip()
                if not plaintext:
                    continue
                password_data = plaintext if not identity else f"{identity}:{plaintext}"
                await self.emit_event(
                    password_data,
                    "PASSWORD",
                    parent=event,
                    context=f'{{module}} cracked hash "{hash_value}" and found {{event.type}}: {{event.data}}',
                )

    async def _extract_emails_from_row(self, row):
        emails = set()
        for value in self._extract_values_by_fields(row, self.email_fields):
            for extracted in await self.helpers.re.extract_emails(value):
                emails.add(extracted)
        return emails

    def _extract_values_by_fields(self, row, field_names):
        values = set()
        for field in field_names:
            value = row.get(field, None)
            if value is None:
                continue
            if isinstance(value, list):
                for nested in value:
                    normalized = str(nested).strip()
                    if normalized:
                        values.add(normalized)
                continue
            normalized = str(value).strip()
            if normalized:
                values.add(normalized)
        return values

    def _split_hashed_password_event(self, event):
        data = str(event.data)
        if ":" in data:
            identity, hash_value = data.split(":", 1)
            return identity.strip(), hash_value.strip()
        return "", data.strip()

    def _safe_json(self, response):
        if response is None:
            return {}
        if getattr(response, "status_code", 0) != 200:
            self.warning(f"Error retrieving results from leak-lookup.com (status code {response.status_code})")
            return {}
        json_result = {}
        with suppress(Exception):
            json_result = response.json()
        return json_result
