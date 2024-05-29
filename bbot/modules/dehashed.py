from contextlib import suppress

from bbot.modules.base import BaseModule


class dehashed(BaseModule):
    watched_events = ["DNS_NAME"]
    produced_events = ["PASSWORD", "HASHED_PASSWORD", "USERNAME"]
    flags = ["passive", "safe", "email-enum"]
    meta = {
        "description": "Execute queries against dehashed.com for exposed credentials",
        "created_date": "2023-10-12",
        "author": "@SpamFaux",
        "auth_required": True,
    }
    options = {"username": "", "api_key": ""}
    options_desc = {"username": "Email Address associated with your API key", "api_key": "DeHashed API Key"}
    target_only = True

    base_url = "https://api.dehashed.com/search"

    async def setup(self):
        self.username = self.config.get("username", "")
        self.api_key = self.config.get("api_key", "")
        self.auth = (self.username, self.api_key)
        self.headers = {
            "Accept": "application/json",
        }

        # soft-fail if we don't have the necessary information to make queries
        if not (self.username and self.api_key):
            return None, "No username / API key set"

        return await super().setup()

    async def handle_event(self, event):
        async for entries in self.query(event):
            for entry in entries:
                # we have to clean up the email field because dehashed does a poor job of it
                email_str = entry.get("email", "").replace("\\", "")
                found_emails = list(self.helpers.extract_emails(email_str))
                if not found_emails:
                    self.debug(f"Invalid email from dehashed.com: {email_str}")
                    continue
                email = found_emails[0]

                user = entry.get("username", "")
                pw = entry.get("password", "")
                h_pw = entry.get("hashed_password", "")
                db_name = entry.get("database_name", "")

                tags = []
                if db_name:
                    tags = [f"db-{db_name}"]
                if email:
                    email_event = self.make_event(email, "EMAIL_ADDRESS", source=event, tags=tags)
                    if email_event is not None:
                        await self.emit_event(email_event)
                        if user:
                            await self.emit_event(f"{email}:{user}", "USERNAME", source=email_event, tags=tags)
                        if pw:
                            await self.emit_event(f"{email}:{pw}", "PASSWORD", source=email_event, tags=tags)
                        if h_pw:
                            await self.emit_event(f"{email}:{h_pw}", "HASHED_PASSWORD", source=email_event, tags=tags)

    async def query(self, event):
        query = f"domain:{event.data}"
        url = f"{self.base_url}?query={query}&size=10000&page=" + "{page}"
        page = 0
        num_entries = 0
        agen = self.helpers.api_page_iter(url=url, auth=self.auth, headers=self.headers, json=False)
        async for result in agen:
            result_json = {}
            with suppress(Exception):
                result_json = result.json()
            total = result_json.get("total", 0)
            entries = result_json.get("entries", [])
            if entries is None:
                entries = []
            num_entries += len(entries)
            page += 1
            if (page >= 3) or (not entries):
                if result is not None and result.status_code != 200:
                    self.warning(
                        f"Error retrieving results from dehashed.com (status code {result.status_code}): {result.text}"
                    )
                elif (page >= 3) and (total > num_entries):
                    self.info(
                        f"{event.data} has {total:,} results in Dehashed. The API can only process the first 30,000 results. Please check dehashed.com to get the remaining results."
                    )
                agen.aclose()
                break
            yield entries
