import json
from bbot.modules.base import BaseModule


ntlm_discovery_endpoints = [
    "",
    "aspnet_client",
    "autodiscover",
    "autodiscover/autodiscover.xml",
    "ecp",
    "ews",
    "ews/exchange.asmx",
    "ews/services.wsdl",
    "exchange",
    "microsoft-server-activesync",
    "microsoft-server-activesync/default.eas",
    "oab",
    "owa",
    "powershell",
    "rpc",
]

NTLM_test_header = {"Authorization": "NTLM TlRMTVNTUAABAAAAl4II4gAAAAAAAAAAAAAAAAAAAAAKAGFKAAAADw=="}


class ntlm(BaseModule):

    watched_events = ["URL", "HTTP_RESPONSE"]
    produced_events = ["FINDING", "DNS_NAME"]
    flags = ["active"]

    in_scope_only = True

    def setup(self):

        self.processed = set()
        return True

    def handle_event(self, event):

        if event.type == "URL":
            result_FQDN, request_url = self.handle_url(event)
            if result_FQDN and request_url:

                self.emit_event(
                    {
                        "host": str(event.host),
                        "url": request_url,
                        "description": f"FOUND NTLM AUTH FQDN: {result_FQDN}",
                    },
                    "FINDING",
                    source=event,
                )
                self.emit_event(result_FQDN, "DNS_NAME", source=event)

        if event.type == "HTTP_RESPONSE":

            split_headers = event.data["response-header"].split("\r\n")
            header_dict = {}
            for i in split_headers:
                if len(i) > 0 and ":" in i:
                    header_dict[i.split(":")[0].lower()] = i.split(":")[1].lstrip()

            if "www-authenticate" in header_dict.keys():
                self.emit_event(
                    {
                        "host": str(event.host),
                        "url": event.data.get("url", ""),
                        "description": f"NTLM Authentication Detected",
                    },
                    "FINDING",
                    source=event,
                )

    def handle_url(self, event):

        ntlm_resp_decoded = self.check_ntlm(event.data)
        if ntlm_resp_decoded:
            url_hash = hash(event.data)
            self.processed.add(url_hash)
            return str(ntlm_resp_decoded["FQDN"]), event.data
        else:
            url_hash = hash(event.parsed.netloc)
            if not url_hash in self.processed:
                self.processed.add(url_hash)
                for endpoint in ntlm_discovery_endpoints:
                    test_url = f"{event.parsed.scheme}://{event.parsed.netloc}/{endpoint}"

                    ntlm_resp_decoded = self.check_ntlm(test_url)
                    if ntlm_resp_decoded:
                        return str(ntlm_resp_decoded["FQDN"]), test_url
        return None, None

    def check_ntlm(self, test_url):

        r = self.helpers.request(test_url, headers=NTLM_test_header)
        ntlm_resp = r.headers.get("WWW-Authenticate", "")
        if ntlm_resp:
            ntlm_resp_b64 = max(ntlm_resp.split(","), key=lambda x: len(x)).replace("NTLM ", "")
            ntlm_resp_decoded = self.helpers.ntlm.ntlmdecode(ntlm_resp_b64)
            return ntlm_resp_decoded
        else:
            return None
