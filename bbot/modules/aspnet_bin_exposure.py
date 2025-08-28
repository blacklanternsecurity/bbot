from bbot.modules.base import BaseModule


class aspnet_bin_exposure(BaseModule):
    watched_events = ["URL"]
    produced_events = ["VULNERABILITY"]
    flags = ["active", "safe", "web-thorough"]
    meta = {
        "description": "Check for ASP.NET Security Feature Bypasses (CVE-2023-36899 and CVE-2023-36560)",
        "created_date": "2025-01-28",
        "author": "@liquidsec",
    }

    in_scope_only = True
    test_dlls = [
        "Telerik.Web.UI.dll",
        "Newtonsoft.Json.dll",
        "System.Net.Http.dll",
        "EntityFramework.dll",
        "AjaxControlToolkit.dll",
    ]

    @staticmethod
    def normalize_url(url):
        return str(url.rstrip("/") + "/").lower()

    def _incoming_dedup_hash(self, event):
        return hash(self.normalize_url(event.data))

    async def handle_event(self, event):
        normalized_url = self.normalize_url(event.data)
        for test_dll in self.test_dlls:
            for technique in ["b/(S(X))in/###DLL_PLACEHOLDER###/(S(X))/", "(S(X))/b/(S(X))in/###DLL_PLACEHOLDER###"]:
                test_url = f"{normalized_url}{technique.replace('###DLL_PLACEHOLDER###', test_dll)}"
                self.debug(f"Sending test URL: [{test_url}]")
                kwargs = {"method": "GET", "allow_redirects": False, "timeout": 10}
                test_result = await self.helpers.request(test_url, **kwargs)
                if test_result:
                    if test_result.status_code == 200 and (
                        "content-type" in test_result.headers
                        and "application/x-msdownload" in test_result.headers["content-type"]
                    ):
                        self.debug(
                            f"Got positive result for probe with test url: [{test_url}]. Status Code: [{test_result.status_code}] Content Length: [{len(test_result.content)}]"
                        )

                        if test_result.status_code == 200 and (
                            "content-type" in test_result.headers
                            and "application/x-msdownload" in test_result.headers["content-type"]
                        ):
                            confirm_url = (
                                f"{normalized_url}{technique.replace('###DLL_PLACEHOLDER###', 'oopsnotarealdll.dll')}"
                            )
                            confirm_result = await self.helpers.request(confirm_url, **kwargs)

                            if confirm_result and (
                                confirm_result.status_code != 200
                                or not (
                                    "content-type" in confirm_result.headers
                                    and "application/x-msdownload" in confirm_result.headers["content-type"]
                                )
                            ):
                                description = f"IIS Bin Directory DLL Exposure. Detection Url: [{test_url}]"
                                await self.emit_event(
                                    {
                                        "severity": "HIGH",
                                        "host": str(event.host),
                                        "url": normalized_url,
                                        "description": description,
                                    },
                                    "VULNERABILITY",
                                    event,
                                    context="{module} detected IIS Bin Directory DLL Exposure vulnerability",
                                )
                                return True

    async def filter_event(self, event):
        if "dir" in event.tags:
            return True
        return False
