from bbot.errors import NTLMError
from bbot.modules.base import BaseModule

ntlm_discovery_endpoints = [
    "",
    "autodiscover/autodiscover.xml",
    "ecp/",
    "ews/",
    "ews/exchange.asmx",
    "exchange/",
    "exchweb/",
    "oab/",
    "owa/",
    "_windows/default.aspx?ReturnUrl=/",
    "abs/",
    "adfs/ls/wia",
    "adfs/services/trust/2005/windowstransport",
    "aspnet_client/",
    "autodiscover/",
    "autoupdate/",
    "certenroll/",
    "certprov/",
    "certsrv/",
    "conf/",
    "debug/",
    "deviceupdatefiles_ext/",
    "deviceupdatefiles_int/",
    "dialin/",
    "etc/",
    "groupexpansion/",
    "hybridconfig/",
    "iwa/authenticated.aspx",
    "iwa/iwa_test.aspx",
    "mcx/",
    "mcx/mcxservice.svc",
    "meet/",
    "meeting/",
    "microsoft-server-activesync/",
    "ocsp/",
    "persistentchat/",
    "phoneconferencing/",
    "powershell/",
    "public/",
    "reach/sip.svc",
    "remoteDesktopGateway/",
    "requesthandler/",
    "requesthandlerext/",
    "rgs/",
    "rgsclients/",
    "rpc/",
    "rpcwithcert/",
    "scheduler/",
    "ucwa/",
    "unifiedmessaging/",
    "webticket/",
    "webticket/webticketservice.svc",
]

NTLM_test_header = {"Authorization": "NTLM TlRMTVNTUAABAAAAl4II4gAAAAAAAAAAAAAAAAAAAAAKAGFKAAAADw=="}


class ntlm(BaseModule):
    """
    Todo:
        Cancel pending requests and break out of loop when valid endpoint is found
        (waiting on https://github.com/encode/httpcore/discussions/783/ to be fixed first)
    """

    watched_events = ["URL", "HTTP_RESPONSE"]
    produced_events = ["FINDING", "DNS_NAME"]
    flags = ["active", "safe", "web-basic"]
    meta = {
        "description": "Watch for HTTP endpoints that support NTLM authentication",
        "created_date": "2022-07-25",
        "author": "@liquidsec",
    }
    options = {"try_all": False}
    options_desc = {"try_all": "Try every NTLM endpoint"}

    in_scope_only = True

    async def setup(self):
        self.found = set()
        self.try_all = self.config.get("try_all", False)
        return True

    async def handle_event(self, event):
        found_hash = hash(f"{event.host}:{event.port}")
        if event.type == "URL":
            url = event.data
        else:
            url = event.data["url"]
        if found_hash in self.found:
            return

        urls = {url}
        if self.try_all:
            for endpoint in ntlm_discovery_endpoints:
                urls.add(f"{event.parsed_url.scheme}://{event.parsed_url.netloc}/{endpoint}")

        num_urls = len(urls)
        agen = self.helpers.request_batch(
            urls, headers=NTLM_test_header, allow_redirects=False, timeout=self.http_timeout
        )
        async for url, response in agen:
            ntlm_resp = response.headers.get("WWW-Authenticate", "")
            if not ntlm_resp:
                continue
            ntlm_resp_b64 = max(ntlm_resp.split(","), key=lambda x: len(x)).split()[-1]
            try:
                ntlm_resp_decoded = self.helpers.ntlm.ntlmdecode(ntlm_resp_b64)
                if not ntlm_resp_decoded:
                    continue

                await agen.aclose()
                self.found.add(found_hash)
                fqdn = ntlm_resp_decoded.get("FQDN", "")
                await self.emit_event(
                    {
                        "host": str(event.host),
                        "url": url,
                        "description": f"NTLM AUTH: {ntlm_resp_decoded}",
                    },
                    "FINDING",
                    parent=event,
                    context=f"{{module}} tried {num_urls:,} NTLM endpoints against {url} and identified NTLM auth ({{event.type}}): {fqdn}",
                )
                fqdn = ntlm_resp_decoded.get("FQDN", "")
                if fqdn:
                    await self.emit_event(fqdn, "DNS_NAME", parent=event)
                break

            except NTLMError as e:
                self.verbose(str(e))

    async def filter_event(self, event):
        if self.try_all:
            return True
        if event.type == "HTTP_RESPONSE":
            if "www-authenticate" in event.data["header-dict"]:
                header_value = event.data["header-dict"]["www-authenticate"][0].lower()
                if "ntlm" in header_value or "negotiate" in header_value:
                    return True
        return False
