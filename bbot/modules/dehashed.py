from bbot.modules.base import BaseModule
from requests.auth import HTTPBasicAuth

class dehashed(BaseModule):
    watched_events = ["EMAIL_ADDRESS"]
    produced_events = ["PASSWORD"]
    flags = ["passive"]
    meta = {"description": "Execute queries against dehash.com for exposed credentials", "auth_required": True}
    options = {"username":"", "api_key": ""}
    options_desc = {"username":"Email Address associated with your API key","api_key": "API Key"}

    base_url = "https://api.dehashed.com/search"

    def setup(self):
        self.username = self.config.get("username", "")
        self.api_key = self.config.get("api_key","")
        self.auth = HTTPBasicAuth(self.username, self.api_key)
        self.headers = {
            "Accept": "application/json",
        }

        self.result_passwords = {}
        self.result_usernames = {}
        self.result_hashed_passwords = {}

        return super().setup()

    def handle_event(self, event):
    
        if event.type == "EMAIL_ADDRESS":
            url = f"{self.base_url}?query=email:{event.data}"
            result = self.helpers.request(url, auth=self.auth, headers=self.headers)
            if result:
                result_json = result.json()
                entries = result_json.get("entries")
                for i in entries:
                    user = i.get("username")
                    pw = i.get("password")
                    h_pw = i.get("hashed_password")
                    db_name = i.get("database_name")
                    
                    # If there is a password result then adds it to dict
                    if pw:
                        self.emit_event(pw, "PASSWORD", source=event)
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
"""
                if self.result_passwords:
                    for x in self.result_passwords:
                        self.emit_event(x, "PASSWORD", source=event)
                if self.result_hashed_passwords:
                    #self.hugesuccess(self.result_hashed_passwords)
                    for x in self.result_hashed_passwords:
                        self.emit_event(x, "HASHED_PASSWORD", source=event)
                if self.result_usernames:
                    self.hugesuccess(self.result_usernames)
"""