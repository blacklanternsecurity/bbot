from contextlib import suppress

from bbot.modules.base import BaseModule


class dehashed(BaseModule):
    watched_events = ["DNS_NAME"]
    produced_events = ["PASSWORD", "HASHED_PASSWORD", "USERNAME"]
    flags = ["passive"]
    meta = {"description": "Execute queries against dehashed.com for exposed credentials", "auth_required": True}
    options = {"username": "", "api_key": ""}
    options_desc = {
        "username": "Email Address associated with your API key",
        "api_key": "DeHashed API Key"
    }

    base_url = "https://api.dehashed.com/search"

    async def setup(self):
        self.username = self.config.get("username", "")
        self.api_key = self.config.get("api_key", "")
        self.auth = (self.username, self.api_key)
        self.headers = {
            "Accept": "application/json",
        }
        self.queries_processed = set()
        self.data_seen = set()

        # soft-fail if we don't have the necessary information to make queries
        if not (self.username and self.api_key):
            return None, "No username / API key set"

        return await super().setup()

    async def filter_event(self, event):
        query = self.make_query(event)
        query_hash = hash(query)
        if query_hash not in self.queries_processed:
            self.queries_processed.add(query_hash)
            return True
        return False, f'Already processed "{query}"'

    async def handle_event(self, event):
        already_seen = set()
        emails = {}

        if event.type == "DNS_NAME":
            query = f"domain:{event.data}"
        else:
            query = f"email:{event.data}"
        url = f"{self.base_url}?query={query}&size=10000&page=" + "{page}"
        async for entries in self.query(url):
            for entry in entries:

                # we have to clean up the email field because dehashed does a poor job of it
                email_str = entry.get("email", "").replace('\\', '')
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
                        self.emit_event(email_event)
                        if user and not self.already_seen(f"{email}:{user}"):
                            self.emit_event(user, "USERNAME", source=email_event, tags=tags)
                        if pw and not self.already_seen(f"{email}:{pw}"):
                            self.emit_event(pw, "PASSWORD", source=email_event, tags=tags)
                        if h_pw and not self.already_seen(f"{email}:{h_pw}"):
                            self.emit_event(h_pw, "HASHED_PASSWORD", source=email_event, tags=tags)

    def already_seen(self, item):
        h = hash(item)
        already_seen = h in self.data_seen
        self.data_seen.add(h)
        return already_seen

    async def query(self, url):
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
                    self.warning(f"Error retrieving results from dehashed.com: {result.text}")
                elif (page >= 3) and (total > num_entries):
                    self.info(
                        f"{event.data} has {total:,} results in Dehashed. The API can only process the first 30,000 results. Please check dehashed.com to get the remaining results."
                    )
                agen.aclose()
                break
            yield entries

    def make_query(self, event):
        if "target" in event.tags:
            return event.data
        _, domain = self.helpers.split_domain(event.data)
        return domain
