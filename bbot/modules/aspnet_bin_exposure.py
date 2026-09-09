from bbot.modules.base import BaseModule


class aspnet_bin_exposure(BaseModule):
    watched_events = ["URL"]
    produced_events = ["FINDING"]
    flags = ["safe", "active", "web-heavy"]
    meta = {
        "description": "Check for ASP.NET Security Feature Bypasses (CVE-2023-36899 and CVE-2023-36560)",
        "created_date": "2025-01-28",
        "author": "@liquidsec",
    }

    in_scope_only = True
    _module_threads = 2

    test_dlls = [
        "Telerik.Web.UI.dll",
        "Newtonsoft.Json.dll",
        "System.Net.Http.dll",
        "EntityFramework.dll",
        "AjaxControlToolkit.dll",
    ]
    _techniques = [
        "b/(S(X))in/###DLL_PLACEHOLDER###/(S(X))/",
        "(S(X))/b/(S(X))in/###DLL_PLACEHOLDER###",
    ]

    @staticmethod
    def normalize_url(url):
        return str(url.rstrip("/") + "/").lower()

    def _incoming_dedup_hash(self, event):
        return hash(self.normalize_url(event.url))

    @staticmethod
    def _is_dll_download(response):
        return (
            response is not None
            and response.status_code == 200
            and "content-type" in response.headers
            and "application/x-msdownload" in response.headers["content-type"]
        )

    async def handle_event(self, event):
        normalized_url = self.normalize_url(event.url)
        kwargs = {"method": "GET", "allow_redirects": False, "timeout": 10}

        probes = []
        for test_dll in self.test_dlls:
            for technique in self._techniques:
                test_url = f"{normalized_url}{technique.replace('###DLL_PLACEHOLDER###', test_dll)}"
                probes.append((test_url, kwargs, technique))

        async for test_url, test_result, technique in self.helpers.request_batch_stream(probes, threads=10):
            if not self._is_dll_download(test_result):
                continue

            self.debug(
                f"Got positive result for probe with test url: [{test_url}]. Status Code: [{test_result.status_code}] Content Length: [{len(test_result.content)}]"
            )

            confirm_url = f"{normalized_url}{technique.replace('###DLL_PLACEHOLDER###', 'oopsnotarealdll.dll')}"
            confirm_result = await self.helpers.request(confirm_url, **kwargs)

            if confirm_result and not self._is_dll_download(confirm_result):
                description = f"IIS Bin Directory DLL Exposure. Detection Url: [{test_url}]"
                await self.emit_event(
                    {
                        "name": "IIS Bin Directory DLL Exposure",
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "host": str(event.host),
                        "url": normalized_url,
                        "description": description,
                    },
                    "FINDING",
                    event,
                    context="{module} detected IIS Bin Directory DLL Exposure vulnerability",
                )
                return True

    async def filter_event(self, event):
        if "dir" in event.tags:
            return True
        return False
