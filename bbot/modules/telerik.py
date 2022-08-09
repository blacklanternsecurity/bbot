from bbot.modules.base import BaseModule
from urllib.parse import urlparse
from sys import executable


class telerik(BaseModule):

    watched_events = ["URL"]
    produced_events = ["VULNERABILITY", "FINDING"]
    flags = ["active", "aggressive", "web"]
    meta = {
        "description": "Scan for critical Telerik vulnerabilities",
    }

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
    RAUConfirmed = []

    options = {"exploit_RAU_crypto": False}
    options_desc = {"exploit_RAU_crypto": "Ettempt to confirm any RAU AXD detections are vulnerable"}

    in_scope_only = True

    deps_pip = ["pycryptodome"]

    deps_ansible = [
        {"name": "Create telerik dir", "file": {"state": "directory", "path": "{BBOT_TOOLS}/telerik/"}},
        {"file": {"state": "touch", "path": "{BBOT_TOOLS}/telerik/testfile.txt"}},
        {
            "name": "Download RAU_crypto",
            "unarchive": {
                "src": "https://github.com/bao7uo/RAU_crypto/archive/refs/heads/master.zip",
                "include": "RAU_crypto-master/RAU_crypto.py",
                "dest": "{BBOT_TOOLS}/telerik/",
                "remote_src": True,
            },
        },
    ]

    def handle_event(self, event):

        webresource = "Telerik.Web.UI.WebResource.axd?type=rau"
        result = self.test_detector(event.data, webresource)
        if result:
            self.debug(result.text)
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
                            output = self.helpers.run(command)
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

        DialogHandlerUrls = [
            "Telerik.Web.UI.DialogHandler.aspx?dp=1",
            "DesktopModules/Admin/RadEditorProvider/DialogHandler.aspx?dp=1",
            "providers/htmleditorproviders/telerik/telerik.web.ui.dialoghandler.aspx",
            "desktopmodules/telerikwebui/radeditorprovider/telerik.web.ui.dialoghandler.aspx",
            "desktopmodules/dnnwerk.radeditorprovider/dialoghandler.aspx",
        ]

        for dh in DialogHandlerUrls:
            result = self.test_detector(event.data, dh)
            if result:
                if "Cannot deserialize dialog parameters" in result.text:
                    self.debug(f"Detected Telerik UI instance ({dh})")
                    description = f"Telerik DialogHandler detected"
                    self.emit_event(
                        {"host": str(event.host), "url": f"{event.data}{dh}", "description": description},
                        "FINDING",
                        event,
                    )

        spellcheckhandler = "Telerik.Web.UI.SpellCheckHandler.axd"
        result = self.test_detector(event.data, spellcheckhandler)
        try:
            # The standard behavior for the spellcheck handler without parameters is a 500
            if result.status_code == 500:
                # Sometimes webapps will just return 500 for everything, so rule out the false positive
                validate_result = self.test_detector(event.data, self.helpers.rand_string())
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

    def test_detector(self, baseurl, detector):

        result = None
        if "/" != baseurl[-1]:
            url = f"{baseurl}/{detector}"
        else:
            url = f"{baseurl}{detector}"
        result = self.helpers.request(url)
        return result

    def filter_event(self, event):

        if "endpoint" in event.tags:
            return False
        else:
            return True
