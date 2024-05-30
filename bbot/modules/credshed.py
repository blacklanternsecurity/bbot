from contextlib import suppress

from bbot.modules.templates.subdomain_enum import subdomain_enum


class credshed(subdomain_enum):
    watched_events = ["DNS_NAME"]
    produced_events = ["PASSWORD", "HASHED_PASSWORD", "USERNAME", "EMAIL_ADDRESS"]
    flags = ["passive", "safe"]
    meta = {
        "description": "Send queries to your own credshed server to check for known credentials of your targets",
        "created_date": "2023-10-12",
        "author": "@SpamFaux",
        "auth_required": True,
    }
    options = {"username": "", "password": "", "credshed_url": ""}
    options_desc = {
        "username": "Credshed username",
        "password": "Credshed password",
        "credshed_url": "URL of credshed server",
    }
    target_only = True

    async def setup(self):
        self.base_url = self.config.get("credshed_url", "").rstrip("/")
        self.username = self.config.get("username", "")
        self.password = self.config.get("password", "")

        # soft-fail if we don't have the necessary information to make queries
        if not (self.base_url and self.username and self.password):
            return None, "Must set username, password, and credshed_url"

        auth_setup = await self.helpers.request(
            f"{self.base_url}/api/auth", method="POST", json={"username": self.username, "password": self.password}
        )
        self.auth_token = ""
        with suppress(Exception):
            self.auth_token = auth_setup.json().get("access_token", "")
        # hard-fail if we didn't get an access token
        if not self.auth_token:
            return False, f"Failed to retrieve credshed auth token from url: {self.base_url}"

        return await super().setup()

    async def handle_event(self, event):
        query = self.make_query(event)
        cs_query = await self.helpers.request(
            f"{self.base_url}/api/search",
            method="POST",
            cookies={"access_token_cookie": self.auth_token},
            json={"query": query},
        )

        if cs_query is not None and cs_query.status_code != 200:
            self.warning(
                f"Error retrieving results from {self.base_url} (status code {cs_query.status_code}): {cs_query.text}"
            )

        json_result = {}
        with suppress(Exception):
            json_result = cs_query.json()

        if not json_result:
            return

        accounts = json_result.get("accounts", [])

        for i in accounts:
            email = i.get("e", "")
            pw = i.get("p", "")
            hashes = i.get("h", [])
            user = i.get("u", "")
            src = i.get("s", [])
            src = [src[0] if src else ""]

            tags = []
            if src:
                tags = [f"credshed-source-{src}"]

            email_event = self.make_event(email, "EMAIL_ADDRESS", parent=event, tags=tags)
            if email_event is not None:
                await self.emit_event(
                    email_event, context=f'{{module}} searched for "{query}" and found {{event.type}}: {{event.data}}'
                )
                if user:
                    await self.emit_event(
                        f"{email}:{user}",
                        "USERNAME",
                        parent=email_event,
                        tags=tags,
                        context=f"{{module}} found {email} with {{event.type}}: {{event.data}}",
                    )
                if pw:
                    await self.emit_event(
                        f"{email}:{pw}",
                        "PASSWORD",
                        parent=email_event,
                        tags=tags,
                        context=f"{{module}} found {email} with {{event.type}}: {{event.data}}",
                    )
                for h_pw in hashes:
                    if h_pw:
                        await self.emit_event(
                            f"{email}:{h_pw}",
                            "HASHED_PASSWORD",
                            parent=email_event,
                            tags=tags,
                            context=f"{{module}} found {email} with {{event.type}}: {{event.data}}",
                        )
