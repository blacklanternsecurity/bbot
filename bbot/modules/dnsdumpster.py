import re
from bs4 import BeautifulSoup

from .base import BaseModule


class dnsdumpster(BaseModule):

    watched_events = ["DOMAIN", "SUBDOMAIN"]
    produced_events = ["SUBDOMAIN"]

    def handle_event(self, event):
        # only process targets
        if not "target" in event.tags:
            return

        query = str(event.data).lower()

        for hostname in self.query(query):
            if hostname in self.scan.target and not hostname == event:
                self.emit_event(hostname, "SUBDOMAIN", event)
            else:
                self.debug(f"Invalid subdomain: {hostname}")

    def query(self, domain):

        ret = []
        # first, get the CSRF tokens
        url = "https://dnsdumpster.com"
        res1 = self.helpers.request(url)
        status_code = getattr(res1, "status_code", 0)
        if status_code not in [200]:
            self.error(f'Bad response code "{status_code}" from DNSDumpster')
            return ret
        else:
            self.debug(f'Valid response code "{status_code}" from DNSDumpster')
        html = BeautifulSoup(res1.content, features="lxml")
        csrftoken = None
        csrfmiddlewaretoken = None
        try:
            for cookie in res1.headers.get("set-cookie", "").split(";"):
                k, v = cookie.split("=", 1)
                if k == "csrftoken":
                    csrftoken = str(v)
            csrfmiddlewaretoken = html.find(
                "input", {"name": "csrfmiddlewaretoken"}
            ).attrs.get("value", None)
        except AttributeError:
            pass

        # Abort if we didn't get the tokens
        if not csrftoken or not csrfmiddlewaretoken:
            self.error("Error obtaining CSRF tokens")
            self.errorState = True
            return ret
        else:
            self.debug("Successfully obtained CSRF tokens")

        # Otherwise, do the needful
        url = "https://dnsdumpster.com/"
        subdomains = set()
        res2 = self.helpers.request(
            url,
            method="POST",
            cookies={"csrftoken": csrftoken},
            data={
                "csrfmiddlewaretoken": csrfmiddlewaretoken,
                "targetip": str(domain).lower(),
                "user": "free",
            },
            headers={
                "origin": "https://dnsdumpster.com",
                "referer": "https://dnsdumpster.com/",
            },
        )
        status_code = getattr(res2, "status_code", 0)
        if status_code not in [200]:
            self.error(f'Bad response code "{status_code}" from DNSDumpster')
            return ret

        html = BeautifulSoup(res2.content, features="lxml")
        escaped_domain = re.escape(domain)
        match_pattern = re.compile(r"^[\w\.-]+\." + escaped_domain + r"$")
        for subdomain in html.findAll(text=match_pattern):
            subdomains.add(str(subdomain).strip().lower())

        return list(subdomains)
