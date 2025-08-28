from contextlib import suppress

from bbot.modules.templates.subdomain_enum import subdomain_enum


class dehashed(subdomain_enum):
    watched_events = ["DNS_NAME"]
    produced_events = ["PASSWORD", "HASHED_PASSWORD", "USERNAME", "EMAIL_ADDRESS"]
    flags = ["passive", "safe", "email-enum"]
    meta = {
        "description": "Execute queries against dehashed.com for exposed credentials",
        "created_date": "2023-10-12",
        "author": "@SpamFaux",
        "auth_required": True,
    }
    options = {"api_key": ""}
    options_desc = {"api_key": "DeHashed API Key"}
    target_only = True

    base_url = "https://api.dehashed.com/v2/search"

    async def setup(self):
        self.api_key = self.config.get("api_key", "")
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Dehashed-Api-Key": self.api_key,
        }

        # soft-fail if we don't have the necessary information to make queries
        if not self.api_key:
            return None, "No API key set"

        return await super().setup()

    async def handle_event(self, event):
        query = self.make_query(event)
        async for entries in self.query(query):
            for entry in entries:
                # we have to clean up the email field because dehashed does a poor job of it
                emails = []
                for email in entry.get("email", []):
                    email_str = email.replace("\\", "")
                    found_emails = list(await self.helpers.re.extract_emails(email_str))
                    if not found_emails:
                        self.debug(f"Invalid email from dehashed.com: {email_str}")
                        continue
                    emails += found_emails

                users = entry.get("username", [])
                pws = entry.get("password", [])
                h_pws = entry.get("hashed_password", [])
                db_name = entry.get("database_name", "")

                tags = []
                if db_name:
                    tags = [f"db-{db_name}"]
                for email in emails:
                    email_event = self.make_event(email, "EMAIL_ADDRESS", parent=event, tags=tags)
                    if email_event is not None:
                        await self.emit_event(
                            email_event,
                            context=f'{{module}} searched API for "{query}" and found {{event.type}}: {{event.data}}',
                        )
                        for user in users:
                            await self.emit_event(
                                f"{email}:{user}",
                                "USERNAME",
                                parent=email_event,
                                tags=tags,
                                context=f"{{module}} found {email} with {{event.type}}: {{event.data}}",
                            )
                        for pw in pws:
                            await self.emit_event(
                                f"{email}:{pw}",
                                "PASSWORD",
                                parent=email_event,
                                tags=tags,
                                context=f"{{module}} found {email} with {{event.type}}: {{event.data}}",
                            )
                        for h_pw in h_pws:
                            await self.emit_event(
                                f"{email}:{h_pw}",
                                "HASHED_PASSWORD",
                                parent=email_event,
                                tags=tags,
                                context=f"{{module}} found {email} with {{event.type}}: {{event.data}}",
                            )

    async def query(self, domain):
        url = self.base_url
        json = {
            "query": "",
            "page": 1,
            "size": 10000,  # The maximum permitted size and pagination.
        }
        json["query"] = f"domain:{domain}"
        json["page"] = 1
        max_pages = 1
        agen = self.api_page_iter(url=url, headers=self.headers, _json=False, method="POST", json=json)
        async for result in agen:
            result_json = {}
            with suppress(Exception):
                result_json = result.json()
            total = result_json.get("total", 0)
            entries = result_json.get("entries", [])
            json["page"] += 1
            if result is not None and result.status_code != 200:
                self.warning(
                    f"Error retrieving results from dehashed.com (status code {result.status_code}): {result.text}"
                )
            elif (json["page"] > max_pages) and (total > (json["size"] * max_pages)):
                self.info(
                    f"{domain} has {total:,} results in Dehashed. The API can only process the first 10,000 results. Please check dehashed.com to get the remaining results."
                )
            if entries:
                yield entries
            if not entries or json["page"] > max_pages:
                await agen.aclose()
                break
