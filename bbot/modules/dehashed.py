from bbot.modules.base import BaseModule
from requests.auth import HTTPBasicAuth


class dehashed(BaseModule):
    watched_events = ["EMAIL_ADDRESS", "DNS_NAME"]
    produced_events = ["PASSWORD", "HASHED_PASSWORD", "USERNAME"]
    flags = ["passive"]
    meta = {"description": "Execute queries against dehashed.com for exposed credentials", "auth_required": True}
    options = {"username": "", "api_key": "", "check_domains": False}
    options_desc = {
        "username": "Email Address associated with your API key",
        "api_key": "API Key",
        "check_domains": "Enable only if bbot should search dehashed for new email addresses - this can be significantly more expensive against the API.",
    }

    base_url = "https://api.dehashed.com/search"

    async def setup(self):
        self.username = self.config.get("username", "")
        self.api_key = self.config.get("api_key", "")
        self.auth = HTTPBasicAuth(self.username, self.api_key)
        self.headers = {
            "Accept": "application/json",
        }
        self.check_domains = self.config.get("check_domains", False)

        self.result_passwords = {}
        self.result_usernames = {}
        self.result_hashed_passwords = {}
        self.result_email = {}
        self.api_balance = 0
        self.api_count = 0
        self.api_warn = False

        return await super().setup()

    async def filter_event(self, event):
        if event.module == self or "subdomain" in event.tags:
            return False
        return True

    def parse_results(self, result, isDNS):
        # If there are no results then leave the function
        if result.json().get("total") == 0:
            return

        self.api_balance = result.json().get("balance")
        self.api_count = result.json().get("total")

        entries = result.json().get("entries")

        # parses the entries
        for i in entries:
            user = i.get("username")
            pw = i.get("password")
            h_pw = i.get("hashed_password")
            email = i.get("email")
            db_name = i.get("database_name")

            if isDNS:
                if email not in self.result_email:
                    self.result_email[email] = {"source": [db_name], "passwords": {}, "hashed": {}, "usernames": {}}
                else:
                    self.result_email[email]["source"].append(db_name)

                if pw:
                    if pw not in self.result_email[email]["passwords"]:
                        self.result_email[email]["passwords"][pw] = [db_name]
                    else:
                        self.result_email[email]["passwords"][pw].append(db_name)

                if h_pw:
                    if h_pw not in self.result_email[email]["hashed"]:
                        self.result_email[email]["hashed"][h_pw] = [db_name]
                    else:
                        self.result_email[email]["hashed"][h_pw].append(db_name)

            else:
                if pw:
                    if pw not in self.result_passwords:
                        self.result_passwords[pw] = [db_name]
                    else:
                        self.result_passwords[pw].append(db_name)

                # If there is a hashed password result then adds it to dict
                if h_pw:
                    if h_pw not in self.result_passwords:
                        self.result_hashed_passwords[h_pw] = [db_name]
                    else:
                        self.result_hashed_passwords[h_pw].append(db_name)

                # If there is a username result then adds it to dict
                if user:
                    if user not in self.result_usernames:
                        self.result_usernames[user] = [db_name]
                    else:
                        self.result_usernames[user].append(db_name)

    async def handle_event(self, event):
        # Checks if user explicitly opted in for domain checking
        if self.check_domains:
            if event.type == "DNS_NAME":
                url = f"{self.base_url}?query=domain:{event.data}&size=10000&page=1"
                result = await self.helpers.request(url, auth=self.auth, headers=self.headers)

                if result:
                    self.parse_results(result, True)

                    # Check to see if multiple requests are required
                    if self.api_count > 10000:
                        pages = self.api_count // 10000
                        if self.api_count % 10000:
                            pages += 1

                        for i in range(2, pages + 1):
                            if i <= 3:
                                url = f"{self.base_url}?query=domain:{event.data}&size=10000&page={i}"
                                result = await self.helpers.request(url, auth=self.auth, headers=self.headers)
                                self.parse_results(result, True)
                            # Due to a limitation in the api we cannot request more thank 30k results or 3 pages of 10k - if we go beyond the 3 pages then break out and warn
                            elif i > 3:
                                self.api_warn = True
                                break

                    for x in self.result_email:
                        f = self.make_event(x, "EMAIL_ADDRESS", source=event, tags=self.result_email[x]["source"])
                        self.emit_event(f)
                        if self.result_email[x]["hashed"]:
                            for y in self.result_email[x]["hashed"]:
                                self.emit_event(y, "HASHED_PASSWORD", source=f, tags=self.result_email[x]["hashed"][y])
                        if self.result_email[x]["passwords"]:
                            for y in self.result_email[x]["passwords"]:
                                self.emit_event(y, "PASSWORD", source=f, tags=self.result_email[x]["passwords"][y])
                        if self.result_email[x]["usernames"]:
                            for y in self.result_email[x]["usernames"]:
                                self.emit_event(y, "USERNAME", source=f, tags=self.result_email[x]["usernames"][y])

        if event.type == "EMAIL_ADDRESS":
            url = f"{self.base_url}?query=email:{event.data}"
            result = await self.helpers.request(url, auth=self.auth, headers=self.headers)
            if result:
                self.parse_results(result, False)

                if self.result_passwords:
                    for x in self.result_passwords:
                        self.emit_event(x, "PASSWORD", source=event, tags=self.result_passwords[x])
                if self.result_hashed_passwords:
                    for x in self.result_hashed_passwords:
                        self.emit_event(x, "HASHED_PASSWORD", source=event, tags=self.result_hashed_passwords[x])
                if self.result_usernames:
                    for x in self.result_usernames:
                        self.emit_event(x, "USERNAME", source=event, tags=self.result_usernames[x])

        if self.api_warn:
            self.info(
                f"{event.data} has {self.api_count} results in Dehashed. The API can only process the first 30,000 results. Please check dehashed.com to get the remaining results."
            )
