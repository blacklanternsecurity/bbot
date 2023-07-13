import asyncio
from sys import executable
from urllib.parse import urlparse

from bbot.modules.base import BaseModule


class telerik(BaseModule):
    watched_events = ["URL"]
    produced_events = ["VULNERABILITY", "FINDING"]
    flags = ["active", "aggressive", "slow", "web-thorough"]
    meta = {"description": "Scan for critical Telerik vulnerabilities"}

    telerikVersions = [
        "2007.1423",
        "2007.1521",
        "2007.1626",
        "2007.2918",
        "2007.21010",
        "2007.21107",
        "2007.31218",
        "2007.31314",
        "2007.31425",
        "2008.1415",
        "2008.1515",
        "2008.1619",
        "2008.2723",
        "2008.2826",
        "2008.21001",
        "2008.31105",
        "2008.31125",
        "2008.31314",
        "2009.1311",
        "2009.1402",
        "2009.1527",
        "2009.2701",
        "2009.2826",
        "2009.31103",
        "2009.31208",
        "2009.31314",
        "2010.1309",
        "2010.1415",
        "2010.1519",
        "2010.2713",
        "2010.2826",
        "2010.2929",
        "2010.31109",
        "2010.31215",
        "2010.31317",
        "2011.1315",
        "2011.1413",
        "2011.1519",
        "2011.2712",
        "2011.2915",
        "2011.31115",
        "2011.3.1305",
        "2012.1.215",
        "2012.1.411",
        "2012.2.607",
        "2012.2.724",
        "2012.2.912",
        "2012.3.1016",
        "2012.3.1205",
        "2012.3.1308",
        "2013.1.220",
        "2013.1.403",
        "2013.1.417",
        "2013.2.611",
        "2013.2.717",
        "2013.3.1015",
        "2013.3.1114",
        "2013.3.1324",
        "2014.1.225",
        "2014.1.403",
        "2014.2.618",
        "2014.2.724",
        "2014.3.1024",
        "2015.1.204",
        "2015.1.225",
        "2015.2.604",
        "2015.2.623",
        "2015.2.729",
        "2015.2.826",
        "2015.3.930",
        "2015.3.1111",
        "2016.1.113",
        "2016.1.225",
        "2016.2.504",
        "2016.2.607",
        "2016.3.914",
        "2016.3.1018",
        "2016.3.1027",
        "2017.1.118",
        "2017.1.228",
        "2017.2.503",
        "2017.2.621",
        "2017.2.711",
        "2017.3.913",
    ]

    DialogHandlerUrls = [
        "Telerik.Web.UI.DialogHandler.aspx",
        "Telerik.Web.UI.DialogHandler.axd",
        "Admin/ServerSide/Telerik.Web.UI.DialogHandler.aspx",
        "App_Master/Telerik.Web.UI.DialogHandler.aspx",
        "AsiCommon/Controls/ContentManagement/ContentDesigner/Telerik.Web.UI.DialogHandler.aspx",
        "cms/portlets/telerik.web.ui.dialoghandler.aspx",
        "common/admin/Calendar/Telerik.Web.UI.DialogHandler.aspx",
        "common/admin/Jobs2/Telerik.Web.UI.DialogHandler.aspx",
        "common/admin/PhotoGallery2/Telerik.Web.UI.DialogHandler.aspx",
        "dashboard/UserControl/CMS/Page/Telerik.Web.UI.DialogHandler.aspx",
        "DesktopModule/UIQuestionControls/UIAskQuestion/Telerik.Web.UI.DialogHandler.aspx",
        "Desktopmodules/Admin/dnnWerk.Users/DialogHandler.aspx",
        "DesktopModules/Admin/RadEditorProvider/DialogHandler.aspx",
        "desktopmodules/base/editcontrols/telerik.web.ui.dialoghandler.aspx",
        "desktopmodules/dnnwerk.radeditorprovider/dialoghandler.aspx",
        "DesktopModules/RadEditorProvider/telerik.web.ui.dialoghandler.aspx",
        "desktopmodules/tcmodules/tccategory/telerik.web.ui.dialoghandler.aspx",
        "desktopmodules/telerikwebui/radeditorprovider/telerik.web.ui.dialoghandler.aspx",
        "DesktopModules/TNComments/Telerik.Web.UI.DialogHandler.aspx",
        "dotnetnuke/DesktopModules/Admin/RadEditorProvider/DialogHandler.aspx",
        "Modules/CMS/Telerik.Web.UI.DialogHandler.aspx",
        "modules/shop/manage/telerik.web.ui.dialoghandler.aspx",
        "portal/channels/fa/Cms_HtmlText_Manage/Telerik.Web.UI.DialogHandler.aspx",
        "providers/htmleditorproviders/telerik/telerik.web.ui.dialoghandler.aspx",
        "Resources/Telerik.Web.UI.DialogHandler.aspx",
        "sitecore/shell/applications/contentmanager/telerik.web.ui.dialoghandler.aspx",
        "sitecore/shell/Controls/RichTextEditor/Telerik.Web.UI.DialogHandler.aspx",
        "Sitefinity/ControlTemplates/Blogs/Telerik.Web.UI.DialogHandler.aspx",
        "SiteTemplates/Telerik.Web.UI.DialogHandler.aspx",
        "static/usercontrols/Telerik.Web.UI.DialogHandler.aspx",
        "system/providers/htmleditor/Telerik.Web.UI.DialogHandler.aspx",
        "WebUIDialogs/Telerik.Web.UI.DialogHandler.aspx",
    ]

    RAUConfirmed = []

    options = {"exploit_RAU_crypto": False}
    options_desc = {"exploit_RAU_crypto": "Attempt to confirm any RAU AXD detections are vulnerable"}

    in_scope_only = True
    per_host_only = True

    deps_pip = ["pycryptodome~=3.17"]

    deps_ansible = [
        {"name": "Create telerik dir", "file": {"state": "directory", "path": "#{BBOT_TOOLS}/telerik/"}},
        {"file": {"state": "touch", "path": "#{BBOT_TOOLS}/telerik/testfile.txt"}},
        {
            "name": "Download RAU_crypto",
            "unarchive": {
                "src": "https://github.com/bao7uo/RAU_crypto/archive/refs/heads/master.zip",
                "include": "RAU_crypto-master/RAU_crypto.py",
                "dest": "#{BBOT_TOOLS}/telerik/",
                "remote_src": True,
            },
        },
    ]

    max_event_handlers = 5

    async def setup(self):
        self.timeout = self.scan.config.get("httpx_timeout", 5)
        return True

    async def handle_event(self, event):
        webresource = "Telerik.Web.UI.WebResource.axd?type=rau"
        result, _ = await self.test_detector(event.data, webresource)
        if result:
            if "RadAsyncUpload handler is registered succesfully" in result.text:
                self.debug(f"Detected Telerik instance (Telerik.Web.UI.WebResource.axd?type=rau)")
                description = f"Telerik RAU AXD Handler detected"
                self.emit_event(
                    {"host": str(event.host), "url": f"{event.data}{webresource}", "description": description},
                    "FINDING",
                    event,
                )
                if self.config.get("exploit_RAU_crypto") == True:
                    hostname = urlparse(event.data).netloc
                    if hostname not in self.RAUConfirmed:
                        self.RAUConfirmed.append(hostname)
                        root_tool_path = self.scan.helpers.tools_dir / "telerik"
                        self.debug(root_tool_path)

                        for version in self.telerikVersions:
                            command = [
                                executable,
                                str(root_tool_path / "RAU_crypto-master/RAU_crypto.py"),
                                "-P",
                                "C:\\\\Windows\\\\Temp",
                                version,
                                str(root_tool_path / "testfile.txt"),
                                result.url,
                            ]
                            output = await self.helpers.run(command)
                            description = f"[CVE-2017-11317] [{str(version)}] {webresource}"
                            if "fileInfo" in output.stdout:
                                self.debug(f"Confirmed Vulnerable Telerik (version: {str(version)}")
                                self.emit_event(
                                    {
                                        "severity": "CRITICAL",
                                        "description": description,
                                        "host": str(event.host),
                                        "url": f"{event.data}{webresource}",
                                    },
                                    "VULNERABILITY",
                                    event,
                                )
                                break

        tasks = []
        for dh in self.DialogHandlerUrls:
            tasks.append(self.helpers.create_task(self.test_detector(event.data, f"{dh}?dp=1")))

        fail_count = 0
        for task in self.helpers.as_completed(tasks):
            try:
                result, dh = await task
            except asyncio.CancelledError:
                continue

            # cancel if we run into timeouts etc.
            if result is None:
                fail_count += 1

                # tolerate some random errors
                if fail_count < 2:
                    continue
                self.debug(f"Cancelling run against {event.data} due to failed request")
                await self.helpers.cancel_tasks(tasks)
                break
            else:
                if "Cannot deserialize dialog parameters" in result.text:
                    await self.helpers.cancel_tasks(tasks)
                    self.debug(f"Detected Telerik UI instance ({dh})")
                    description = f"Telerik DialogHandler detected"
                    self.emit_event(
                        {"host": str(event.host), "url": f"{event.data}{dh}", "description": description},
                        "FINDING",
                        event,
                    )
                    # Once we have a match we need to stop, because the basic handler (Telerik.Web.UI.DialogHandler.aspx) usually works with a path wildcard
                    break

        await self.helpers.cancel_tasks(tasks)

        spellcheckhandler = "Telerik.Web.UI.SpellCheckHandler.axd"
        result, _ = await self.test_detector(event.data, spellcheckhandler)
        try:
            # The standard behavior for the spellcheck handler without parameters is a 500
            if result.status_code == 500:
                # Sometimes webapps will just return 500 for everything, so rule out the false positive
                validate_result, _ = await self.test_detector(event.data, self.helpers.rand_string())
                self.debug(validate_result)
                if validate_result.status_code != 500:
                    self.debug(f"Detected Telerik UI instance (Telerik.Web.UI.SpellCheckHandler.axd)")
                    description = f"Telerik SpellCheckHandler detected"
                    self.emit_event(
                        {
                            "host": str(event.host),
                            "url": f"{event.data}{spellcheckhandler}",
                            "description": description,
                        },
                        "FINDING",
                        event,
                    )
        except Exception:
            pass

    async def test_detector(self, baseurl, detector):
        result = None
        if "/" != baseurl[-1]:
            url = f"{baseurl}/{detector}"
        else:
            url = f"{baseurl}{detector}"
        result = await self.helpers.request(url, timeout=self.timeout)
        return result, detector

    async def filter_event(self, event):
        if "endpoint" in event.tags:
            return False
        else:
            return True
