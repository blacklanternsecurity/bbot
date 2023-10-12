from contextlib import suppress

from bbot.modules.base import BaseModule


class credshed(BaseModule):
    watched_events = ["EMAIL_ADDRESS", "DNS_NAME"]
    produced_events = ["PASSWORD", "HASHED_PASSWORD", "USERNAME", "EMAIL_ADDRESS"]
    flags = ["passive", "safe"]
    meta = {
        "description": "Send queries to your own credshed server to check for known credentials of your targets",
        "auth_required": True,
    }
    options = {"username": "", "password": "", "credshed_url": ""}
    options_desc = {
        "username": "Credshed username",
        "password": "Credshed password",
        "credshed_url": "URL of credshed server",
    }

    async def setup(self):
        self.base_url = self.config.get("credshed_url", "").rstrip("/")
        self.username = self.config.get("username", "")
        self.password = self.config.get("password", "")
        self.results = {}

        if not (self.base_url and self.username and self.password):
            return None, "Must set username, password, and credshed_url"

        auth_setup = await self.helpers.request(
            f"{self.base_url}/api/auth", method="POST", json={"username": self.username, "password": self.password}
        )
        self.auth_token = ""
        with suppress(Exception):
            self.auth_token = auth_setup.json().get("access_token", "")
        if not self.auth_token:
            return None, f"Failed to retrieve credshed auth token from url: {self.base_url}"

        return await super().setup()

    async def filter_event(self, event):
        if event.module == self or "subdomain" in event.tags:
            return False
        return True

    async def handle_event(self, event):
        self.critical(event)
        cs_query = await self.helpers.request(
            f"{self.base_url}/api/search",
            method="POST",
            cookies={"access_token_cookie": self.auth_token},
            json={"query": event.data},
        )

        if cs_query and cs_query.json().get("stats").get("total_count") > 0:
            accounts = cs_query.json().get("accounts")
            for i in accounts:
                email = i.get("e")
                pw = i.get("p")
                h_pw = i.get("h")
                user = i.get("u")
                src = i.get("s")[0]
                if email not in self.results:
                    self.results[email] = {"source": [src], "passwords": {}, "hashed": {}, "usernames": {}}
                else:
                    if src not in self.results[email]["source"]:
                        self.results[email]["source"].append(src)

                if pw:
                    if pw not in self.results[email]["passwords"]:
                        self.results[email]["passwords"][pw] = [src]
                    else:
                        self.results[email]["passwords"][pw].append(src)

                if h_pw:
                    for x in h_pw:
                        if x not in self.results[email]["hashed"]:
                            self.results[email]["hashed"][x] = [src]
                        else:
                            self.results[email]["hashed"][x].append(src)

                if user:
                    if user not in self.results[email]["usernames"]:
                        self.results[email]["usernames"][user] = [src]
                    else:
                        self.results[email]["usernames"][user].append(src)

            for x in self.results:
                if cs_query.json().get("stats").get("query_type") == "domain":
                    f = self.make_event(x, "EMAIL_ADDRESS", source=event, tags="credshed")
                    self.emit_event(f)

                    if self.results[x]["hashed"]:
                        for y in self.results[x]["hashed"]:
                            self.emit_event(
                                y, "HASHED_PASSWORD", source=f, tags=f'credshed-source-{self.results[x]["hashed"][y]}'
                            )

                    if self.results[x]["passwords"]:
                        for y in self.results[x]["passwords"]:
                            self.emit_event(
                                y, "PASSWORD", source=f, tags=f'credshed-source-{self.results[x]["passwords"][y]}'
                            )

                    if self.results[x]["usernames"]:
                        for y in self.results[x]["usernames"]:
                            self.emit_event(
                                y, "USERNAME", source=f, tags=f'credshed-source-{self.results[x]["usernames"][y]}'
                            )

                if cs_query.json().get("stats").get("query_type") == "email":
                    if self.results[x]["hashed"]:
                        for y in self.results[x]["hashed"]:
                            self.emit_event(
                                y,
                                "HASHED_PASSWORD",
                                source=event,
                                tags=f'credshed-source-{self.results[x]["hashed"][y]}',
                            )

                    if self.results[x]["passwords"]:
                        for y in self.results[x]["passwords"]:
                            self.emit_event(
                                y, "PASSWORD", source=event, tags=f'credshed-source-{self.results[x]["passwords"][y]}'
                            )

                    if self.results[x]["usernames"]:
                        for y in self.results[x]["usernames"]:
                            self.emit_event(
                                y, "USERNAME", source=event, tags=f'credshed-source-{self.results[x]["usernames"][y]}'
                            )
