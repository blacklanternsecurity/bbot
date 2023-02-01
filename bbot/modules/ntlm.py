from threading import Lock

from bbot.modules.base import BaseModule
from bbot.core.errors import NTLMError, RequestException

ntlm_discovery_endpoints = [
    "",
    "autodiscover/autodiscover.xml" "ecp/",
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
    watched_events = ["URL", "HTTP_RESPONSE"]
    produced_events = ["FINDING", "DNS_NAME"]
    flags = ["active", "safe", "web-basic"]
    meta = {"description": "Watch for HTTP endpoints that support NTLM authentication"}
    options = {"max_threads": 10, "try_all": False}
    options_desc = {"max_threads": "Maximum concurrent requests", "try_all": "Try every NTLM endpoint"}

    in_scope_only = True

    def setup(self):
        self.processed = set()
        self.processed_lock = Lock()
        self.found = set()
        self.try_all = self.config.get("try_all", False)
        return True

    def handle_event(self, event):
        found_hash = hash(f"{event.host}:{event.port}")
        if found_hash not in self.found:
            result_FQDN, request_url = self.handle_url(event)
            if result_FQDN and request_url:
                self.found.add(found_hash)
                self.emit_event(
                    {
                        "host": str(event.host),
                        "url": request_url,
                        "description": f"NTLM AUTH: {result_FQDN}",
                    },
                    "FINDING",
                    source=event,
                )
                self.emit_event(result_FQDN, "DNS_NAME", source=event)

    def filter_event(self, event):
        if self.try_all:
            return True
        if event.type == "HTTP_RESPONSE":
            if "www-authenticate" in event.data["header-dict"]:
                header_value = event.data["header-dict"]["www-authenticate"].lower()
                if "ntlm" in header_value or "negotiate" in header_value:
                    return True
        return False

    def handle_url(self, event):
        if event.type == "URL":
            urls = {
                event.data,
            }
        else:
            urls = {
                event.data["url"],
            }
        if self.try_all:
            for endpoint in ntlm_discovery_endpoints:
                urls.add(f"{event.parsed.scheme}://{event.parsed.netloc}/{endpoint}")

        futures = {}
        for url in urls:
            future = self.submit_task(self.check_ntlm, url)
            futures[future] = url

        for future in self.helpers.as_completed(futures):
            url = futures[future]
            try:
                result = future.result()
                if result:
                    for future in futures:
                        future.cancel()
                    return str(result["FQDN"]), url
            except RequestException as e:
                self.warning(str(e))

        return None, None

    def check_ntlm(self, test_url):
        url_hash = hash(test_url)

        with self.processed_lock:
            if url_hash in self.processed:
                return
            self.processed.add(url_hash)

        # use lower timeout value
        http_timeout = self.config.get("httpx_timeout", 5)
        r = self.helpers.request(
            test_url, headers=NTLM_test_header, raise_error=True, allow_redirects=False, timeout=http_timeout
        )
        ntlm_resp = r.headers.get("WWW-Authenticate", "")
        if ntlm_resp:
            ntlm_resp_b64 = max(ntlm_resp.split(","), key=lambda x: len(x)).split()[-1]
            try:
                ntlm_resp_decoded = self.helpers.ntlm.ntlmdecode(ntlm_resp_b64)
                if ntlm_resp_decoded:
                    return ntlm_resp_decoded
            except NTLMError as e:
                self.verbose(str(e))
