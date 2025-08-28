import json
import re
import base64

from .base import ModuleTestBase, tempwordlist
from werkzeug.wrappers import Response
from urllib.parse import unquote, quote

import xml.etree.ElementTree as ET

from .test_module_paramminer_headers import helper


# Path Traversal single dot tolerance
class Test_Lightfuzz_path_singledot(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "lightfuzz", "excavate"]
    config_overrides = {
        "interactsh_disable": True,
        "modules": {
            "lightfuzz": {
                "enabled_submodules": ["path"],
            }
        },
    }

    async def setup_after_prep(self, module_test):
        expect_args = re.compile("/images")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)
        respond_args = {
            "response_data": '"<section class="images"><img src="/images?filename=default.jpg"></section>',
            "status": 200,
        }

        expect_args = {"method": "GET", "uri": "/"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def request_handler(self, request):
        qs = str(request.query_string.decode())
        if "filename=" in qs:
            value = qs.split("=")[1]

            if "&" in value:
                value = value.split("&")[0]

            block = """
<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1">
  <rect width="1" height="1" fill="black"/>
</svg>
        """
            if value == "%2F.%2Fa%2F..%2Fdefault.jpg" or value == "default.jpg":
                return Response(block, status=200)
        return Response("file not found", status=500)

    def check(self, module_test, events):
        web_parameter_emitted = False
        pathtraversal_finding_emitted = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [filename]" in e.data["description"]:
                    web_parameter_emitted = True

            if e.type == "FINDING":
                if (
                    "POSSIBLE Path Traversal. Parameter: [filename] Parameter Type: [GETPARAM] Original Value: [default.jpg] Detection Method: [single-dot traversal tolerance (url-encoding, leading slash)]"
                    in e.data["description"]
                ):
                    pathtraversal_finding_emitted = True

        assert web_parameter_emitted, "WEB_PARAMETER was not emitted"
        assert pathtraversal_finding_emitted, "Path Traversal single dot tolerance FINDING not emitted"


# Path Traversal Absolute path
class Test_Lightfuzz_path_absolute(Test_Lightfuzz_path_singledot):
    etc_passwd = """
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
"""

    async def setup_after_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/images", "query_string": "filename=/etc/passwd"}
        respond_args = {"response_data": self.etc_passwd}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/images"}
        respond_args = {"response_data": "<html><head><body><p>ERROR: Invalid File</p></body></html>", "status": 200}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {
            "response_data": '"<section class="images"><img src="/images?filename=default.jpg"></section>',
            "status": 200,
        }
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        web_parameter_emitted = False
        pathtraversal_finding_emitted = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [filename]" in e.data["description"]:
                    web_parameter_emitted = True

            if e.type == "FINDING":
                if (
                    "POSSIBLE Path Traversal. Parameter: [filename] Parameter Type: [GETPARAM] Original Value: [default.jpg] Detection Method: [Absolute Path: /etc/passwd]"
                    in e.data["description"]
                ):
                    pathtraversal_finding_emitted = True

        assert web_parameter_emitted, "WEB_PARAMETER was not emitted"
        assert pathtraversal_finding_emitted, "Path Traversal single dot tolerance FINDING not emitted"


# SSTI Integer Multiplcation
class Test_Lightfuzz_ssti_multiply(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "lightfuzz", "excavate"]
    config_overrides = {
        "interactsh_disable": True,
        "modules": {
            "lightfuzz": {
                "enabled_submodules": ["ssti"],
            }
        },
    }

    def request_handler(self, request):
        qs = str(request.query_string.decode())
        if "data=" in qs:
            value = qs.split("=")[1]
            if "&" in value:
                value = value.split("&")[0]
            nums = value.split("%20")[1].split("*")
            ints = [int(s) for s in nums]
            ssti_block = f"<html><div class=data>{str(ints[0] * ints[1])}</div</html>"
        return Response(ssti_block, status=200)

    async def setup_after_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "", "status": 302, "headers": {"Location": "/test?data=9"}}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = re.compile("/test.*")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

    def check(self, module_test, events):
        web_parameter_emitted = False
        ssti_finding_emitted = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [data]" in e.data["description"]:
                    web_parameter_emitted = True

            if e.type == "FINDING":
                if (
                    "POSSIBLE Server-side Template Injection. Parameter: [data] Parameter Type: [GETPARAM] Original Value: [9] Detection Method: [Integer Multiplication]"
                    in e.data["description"]
                ):
                    ssti_finding_emitted = True

        assert web_parameter_emitted, "WEB_PARAMETER was not emitted"
        assert ssti_finding_emitted, "SSTI integer multiply FINDING not emitted"


# Between Tags XSS Detection
class Test_Lightfuzz_xss(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "lightfuzz", "excavate"]
    config_overrides = {
        "interactsh_disable": True,
        "modules": {
            "lightfuzz": {
                "enabled_submodules": ["xss"],
            }
        },
    }

    def request_handler(self, request):
        qs = str(request.query_string.decode())

        parameter_block = """
        <section class=search>
            <form action=/ method=GET>
                <input type=text placeholder='Search the blog...' name=search>
                <button type=submit class=button>Search</button>
            </form>
        </section>
        """
        if "search=" in qs:
            value = qs.split("=")[1]
            if "&" in value:
                value = value.split("&")[0]
            xss_block = f"""
        <section class=blog-header>
            <h1>0 search results for '{unquote(value)}'</h1>
            <hr>
        </section>
        """
            return Response(xss_block, status=200)
        return Response(parameter_block, status=200)

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["lightfuzz"].helpers.rand_string = lambda *args, **kwargs: "AAAAAAAAAAAAAA"
        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

    def check(self, module_test, events):
        web_parameter_emitted = False
        xss_finding_emitted = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [search]" in e.data["description"]:
                    web_parameter_emitted = True

            if e.type == "FINDING":
                if "Possible Reflected XSS. Parameter: [search] Context: [Between Tags" in e.data["description"]:
                    xss_finding_emitted = True

        assert web_parameter_emitted, "WEB_PARAMETER was not emitted"
        assert xss_finding_emitted, "Between Tags XSS FINDING not emitted"


# Form Action Injection Detection
class Test_Lightfuzz_xss_formaction(Test_Lightfuzz_xss):
    def request_handler(self, request):
        form_data = request.form
        value = form_data.get("func", None)

        parameter_block = """
        <section class=search>
            <form action="/" method=POST>
                <input type=text placeholder='Search the blog...' name=search>
                <input type=text name=func value="/">
                <button type=submit class=button>Search</button>
            </form>
        </section>
        """

        if value:
            xss_block = f"""
            <section class=search>
                <form action="{value}" method=POST>
                    <input type=text placeholder='Search the blog...' name=search>
                    <input type=text name=func value="{value}">
                    <button type=submit class=button>Search</button>
                </form>
            </section>
            """

            return Response(xss_block, status=200)

        return Response(parameter_block, status=200)

    def check(self, module_test, events):
        web_parameter_emitted = False
        xss_finding_emitted = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [search]" in e.data["description"]:
                    web_parameter_emitted = True

            if e.type == "FINDING":
                if (
                    "Possible Reflected XSS. Parameter: [func] Context: [Form Action Injection] Parameter Type: [POSTPARAM]"
                    in e.data["description"]
                ):
                    xss_finding_emitted = True

        assert web_parameter_emitted, "WEB_PARAMETER was not emitted"
        assert xss_finding_emitted, "Form Action XSS FINDING not emitted"


# Base64 Envelope XSS Detection
class Test_Lightfuzz_envelope_base64(Test_Lightfuzz_xss):
    def request_handler(self, request):
        qs = str(request.query_string.decode())

        parameter_block = """
        <section class=search>
            <form action=/ method=GET>
                <input type=text value='dGV4dA==' name=search>
                <button type=submit class=button>Search</button>
            </form>
        </section>
        """
        if "search=" in qs:
            value = qs.split("search=")[1]
            if "&" in value:
                value = value.split("&")[0]

            xss_block = f"""
        <section class=blog-header>
            <h1>0 search results for '{unquote(base64.b64decode(unquote(value)))}'</h1>
            <hr>
        </section>
        """
            return Response(xss_block, status=200)
        return Response(parameter_block, status=200)

    def check(self, module_test, events):
        web_parameter_emitted = False
        xss_finding_emitted = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [search]" in e.data["description"]:
                    web_parameter_emitted = True

            if e.type == "FINDING":
                if (
                    "Possible Reflected XSS. Parameter: [search] Context: [Between Tags (z tag)"
                    in e.data["description"]
                ):
                    xss_finding_emitted = True

        assert web_parameter_emitted, "WEB_PARAMETER was not emitted"
        assert xss_finding_emitted, "Between Tags XSS FINDING not emitted"


# Hex Envelope XSS Detection
class Test_Lightfuzz_envelope_hex(Test_Lightfuzz_envelope_base64):
    def request_handler(self, request):
        qs = str(request.query_string.decode())

        parameter_block = """
        <section class=search>
            <form action=/ method=GET>
                <input type=text value='7b22736561726368223a202264656d6f6b6579776f7264227d' name=search>
                <button type=submit class=button>Search</button>
            </form>
        </section>
        """

        if "search=" in qs:
            value = qs.split("search=")[1]
            if "&" in value:
                value = value.split("&")[0]

            try:
                # Decode the hex value
                decoded_value = bytes.fromhex(unquote(value)).decode()

                # Parse the decoded value as JSON
                json_data = json.loads(decoded_value)

                # Extract the desired parameter from the JSON (e.g., 'search')
                if "search" in json_data:
                    extracted_value = json_data["search"]
                else:
                    extracted_value = "[Parameter not found in JSON]"

            except (json.JSONDecodeError, ValueError):
                extracted_value = "[Invalid hex or JSON format]"

            xss_block = f"""
        <section class=blog-header>
            <h1>0 search results for '{extracted_value}'</h1>
            <hr>
        </section>
        """
            return Response(xss_block, status=200)
        return Response(parameter_block, status=200)


# Base64 (JSON) Envelope XSS Detection
class Test_Lightfuzz_envelope_jsonb64(Test_Lightfuzz_envelope_base64):
    def request_handler(self, request):
        qs = str(request.query_string.decode())

        parameter_block = """
        <section class=search>
            <form action=/ method=GET>
                <input type=text value='eyJzZWFyY2giOiAiZGVtb2tleXdvcmQifQ==' name=search>
                <button type=submit class=button>Search</button>
            </form>
        </section>
        """

        if "search=" in qs:
            value = qs.split("search=")[1]
            if "&" in value:
                value = value.split("&")[0]

            try:
                # Base64 decode the value
                decoded_value = base64.b64decode(unquote(value)).decode()

                # Parse the decoded value as JSON
                json_data = json.loads(decoded_value)

                # Extract the desired parameter from the JSON (e.g., 'search')
                if "search" in json_data:
                    extracted_value = json_data["search"]
                else:
                    extracted_value = "[Parameter not found in JSON]"

            except (json.JSONDecodeError, base64.binascii.Error):
                extracted_value = "[Invalid base64 or JSON format]"

            xss_block = f"""
        <section class=blog-header>
            <h1>0 search results for '{extracted_value}'</h1>
            <hr>
        </section>
        """
            return Response(xss_block, status=200)

        return Response(parameter_block, status=200)


# Base64 (JSON) Multiple Envelope Detection
class Test_Lightfuzz_envelope_multiple_json(Test_Lightfuzz_envelope_base64):
    def request_handler(self, request):
        parameter_block = """
        <section class=search>
            <form action=/ method=GET>
                <input type=text value='%65%79%4a%7a%64%48%4a%70%62%6d%63%78%49%6a%6f%69%64%6d%46%73%64%57%55%78%49%69%77%69%63%33%52%79%61%57%35%6e%4d%69%49%36%49%6e%5a%68%62%48%56%6c%4d%69%4a%39' name=search>
                <button type=submit class=button>Search</button>
            </form>
        </section>
        """
        return Response(parameter_block, status=200)

    def check(self, module_test, events):
        web_parameter_emitted = False
        web_parameter_clone_emitted = False

        for e in events:
            if e.type == "WEB_PARAMETER":
                for subparam in e.envelopes.get_subparams():
                    if len(subparam[0]) > 0:
                        if subparam[0][0] == "string1" and subparam[1] == "value1":
                            web_parameter_emitted = True
                        if subparam[0][0] == "string2" and subparam[1] == "value2":
                            web_parameter_clone_emitted = True

        assert web_parameter_emitted, "WEB_PARAMETER was not emitted"
        assert web_parameter_clone_emitted, "WEB_PARAMETER clone was not emitted"


# Base64 (XML) Envelope XSS Detection
class Test_Lightfuzz_envelope_xmlb64(Test_Lightfuzz_envelope_base64):
    def request_handler(self, request):
        qs = str(request.query_string.decode())

        parameter_block = """
        <section class=search>
            <form action=/ method=GET>
                <input type=text value='PGZpbmQ+PHNlYXJjaD5kZW1va2V5d29yZDwvc2VhcmNoPjwvZmluZD4=' name=search>
                <button type=submit class=button>Search</button>
            </form>
        </section>
        """

        if "search=" in qs:
            value = qs.split("search=")[1]
            if "&" in value:
                value = value.split("&")[0]

            try:
                # Base64 decode the value
                decoded_value = base64.b64decode(unquote(value)).decode()

                # Parse the decoded value as XML
                root = ET.fromstring(decoded_value)

                # Extract the desired parameter from the XML (e.g., 'search')
                search_element = root.find(".//search")
                if search_element is not None:
                    extracted_value = search_element.text
                else:
                    extracted_value = "[Parameter not found in XML]"

            except (ET.ParseError, base64.binascii.Error):
                extracted_value = "[Invalid base64 or XML format]"

            xss_block = f"""
        <section class=blog-header>
            <h1>0 search results for '{extracted_value}'</h1>
            <hr>
        </section>
        """
            return Response(xss_block, status=200)

        return Response(parameter_block, status=200)


# In Tag Attribute XSS Detection
class Test_Lightfuzz_xss_intag(Test_Lightfuzz_xss):
    def request_handler(self, request):
        qs = str(request.query_string.decode())

        parameter_block = """
        <html>
            <a href="/otherpage.php?foo=bar">Link</a>
        </html>
        """
        if "foo=" in qs:
            value = qs.split("=")[1]
            if "&" in value:
                value = value.split("&")[0]

            xss_block = f"""
        <section class=blog-header>
            <div something="{unquote(value)}">stuff</div>
            <hr>
        </section>
        """
            return Response(xss_block, status=200)
        return Response(parameter_block, status=200)

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["lightfuzz"].helpers.rand_string = lambda *args, **kwargs: "AAAAAAAAAAAAAA"
        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)
        expect_args = re.compile("/otherpage.php")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

    def check(self, module_test, events):
        web_parameter_emitted = False
        original_value_captured = False
        xss_finding_emitted = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [foo]" in e.data["description"]:
                    web_parameter_emitted = True
                    if e.data["original_value"] == "bar":
                        original_value_captured = True

            if e.type == "FINDING":
                if "Possible Reflected XSS. Parameter: [foo] Context: [Tag Attribute]" in e.data["description"]:
                    xss_finding_emitted = True

        assert web_parameter_emitted, "WEB_PARAMETER was not emitted"
        assert original_value_captured, "original_value not captured"
        assert xss_finding_emitted, "Between Tags XSS FINDING not emitted"


# In Javascript XSS Detection
class Test_Lightfuzz_xss_injs(Test_Lightfuzz_xss):
    parameter_block = """
        <html>
            <a href="/otherpage.php?language=en">Link</a>
        </html>
        """

    def request_handler(self, request):
        qs = str(request.query_string.decode())
        if "language=" in qs:
            value = qs.split("=")[1]

            if "&" in value:
                value = value.split("&")[0]

            xss_block = f"""
<html>
<head>
<script>
var lang = '{unquote(value)}';
console.log(lang);
</script>
</head>
<body>
<p>test</p>
</body>
</html>
        """
            return Response(xss_block, status=200)
        return Response(self.parameter_block, status=200)

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["lightfuzz"].helpers.rand_string = lambda *args, **kwargs: "AAAAAAAAAAAAAA"
        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)
        expect_args = re.compile("/otherpage.php")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

    def check(self, module_test, events):
        web_parameter_emitted = False
        original_value_captured = False
        xss_finding_emitted = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [language]" in e.data["description"]:
                    web_parameter_emitted = True
                    if e.data["original_value"] == "en":
                        original_value_captured = True

            if e.type == "FINDING":
                if "Possible Reflected XSS. Parameter: [language] Context: [In Javascript]" in e.data["description"]:
                    xss_finding_emitted = True

        assert web_parameter_emitted, "WEB_PARAMETER was not emitted"
        assert original_value_captured, "original_value not captured"
        assert xss_finding_emitted, "In Javascript XSS FINDING not emitted"


# XSS Parameter Needing URL-Encoding
class Test_Lightfuzz_urlencoding(Test_Lightfuzz_xss_injs):
    config_overrides = {
        "interactsh_disable": True,
        "modules": {
            "lightfuzz": {
                "enabled_submodules": ["cmdi", "crypto", "path", "serial", "sqli", "ssti", "xss"],
            }
        },
    }

    parameter_block = """
        <html>
            <a href="/otherpage.php?language=parameter with spaces">Link</a>
        </html>
        """

    def check(self, module_test, events):
        web_parameter_emitted = False
        original_value_captured = False
        xss_finding_emitted = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [language]" in e.data["description"]:
                    web_parameter_emitted = True
                    if e.data["original_value"] is not None and e.data["original_value"] == "parameter with spaces":
                        original_value_captured = True

            if e.type == "FINDING":
                if "Possible Reflected XSS. Parameter: [language] Context: [In Javascript]" in e.data["description"]:
                    xss_finding_emitted = True

        assert web_parameter_emitted, "WEB_PARAMETER was not emitted"
        assert original_value_captured, "original_value not captured"
        assert xss_finding_emitted, "In Javascript XSS FINDING not emitted"


# SQLI Single Quote/Two Single Quote (getparam)
class Test_Lightfuzz_sqli(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "lightfuzz", "excavate"]
    config_overrides = {
        "interactsh_disable": True,
        "modules": {
            "lightfuzz": {
                "enabled_submodules": ["sqli"],
            }
        },
    }

    def request_handler(self, request):
        qs = str(request.query_string.decode())
        parameter_block = """
        <section class=search>
            <form action=/ method=GET>
                <input type=text placeholder='Search the blog...' name=search>
                <button type=submit class=button>Search</button>
            </form>
        </section>
        """
        if "search=" in qs:
            value = qs.split("=")[1]

            if "&" in value:
                value = value.split("&")[0]

            sql_block_normal = f"""
        <section class=blog-header>
            <h1>0 search results for '{unquote(value)}'</h1>
            <hr>
        </section>
        """

            sql_block_error = """
        <section class=error>
            <h1>Found error in SQL query</h1>
            <hr>
        </section>
        """
            if value.endswith("'"):
                if value.endswith("''"):
                    return Response(sql_block_normal, status=200)
                return Response(sql_block_error, status=500)
        return Response(parameter_block, status=200)

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["lightfuzz"].helpers.rand_string = lambda *args, **kwargs: "AAAAAAAAAAAAAA"
        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

    def check(self, module_test, events):
        web_parameter_emitted = False
        sqli_finding_emitted = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [search]" in e.data["description"]:
                    web_parameter_emitted = True
            if e.type == "FINDING":
                if (
                    "Possible SQL Injection. Parameter: [search] Parameter Type: [GETPARAM] Detection Method: [Single Quote/Two Single Quote, Code Change (200->500->200)]"
                    in e.data["description"]
                ):
                    sqli_finding_emitted = True

        assert web_parameter_emitted, "WEB_PARAMETER was not emitted"
        assert sqli_finding_emitted, "SQLi Single/Double Quote getparam FINDING not emitted"


# SQLI Single Quote/Two Single Quote (postparam)
class Test_Lightfuzz_sqli_post(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "lightfuzz", "excavate"]
    config_overrides = {
        "interactsh_disable": True,
        "modules": {
            "lightfuzz": {
                "enabled_submodules": ["sqli"],
            }
        },
    }

    def request_handler(self, request):
        parameter_block = """
        <section class=search>
            <form action=/ method=POST>
                <input type=text placeholder='Search the blog...' name=search>
                <button type=submit class=button>Search</button>
            </form>
        </section>
        """

        if "search" in request.form.keys():
            value = request.form["search"]

            sql_block_normal = f"""
        <section class=blog-header>
            <h1>0 search results for '{unquote(value)}'</h1>
            <hr>
        </section>
        """

            sql_block_error = """
        <section class=error>
            <h1>Found error in SQL query</h1>
            <hr>
        </section>
        """
            if value.endswith("'"):
                if value.endswith("''"):
                    return Response(sql_block_normal, status=200)
                return Response(sql_block_error, status=500)
        return Response(parameter_block, status=200)

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["lightfuzz"].helpers.rand_string = lambda *args, **kwargs: "AAAAAAAAAAAAAA"
        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

    def check(self, module_test, events):
        web_parameter_emitted = False
        sqli_finding_emitted = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [search]" in e.data["description"]:
                    web_parameter_emitted = True

            if e.type == "FINDING":
                if (
                    "Possible SQL Injection. Parameter: [search] Parameter Type: [POSTPARAM] Detection Method: [Single Quote/Two Single Quote, Code Change (200->500->200)]"
                    in e.data["description"]
                ):
                    sqli_finding_emitted = True

        assert web_parameter_emitted, "WEB_PARAMETER was not emitted"
        assert sqli_finding_emitted, "SQLi Single/Double Quote postparam FINDING not emitted"


# disable_post test
class Test_Lightfuzz_disable_post(Test_Lightfuzz_sqli_post):
    config_overrides = {
        "interactsh_disable": True,
        "modules": {
            "lightfuzz": {
                "enabled_submodules": ["sqli"],
                "disable_post": True,
            }
        },
    }

    def check(self, module_test, events):
        web_parameter_emitted = False
        sqli_finding_emitted = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [search]" in e.data["description"]:
                    web_parameter_emitted = True

            if e.type == "FINDING":
                if (
                    "Possible SQL Injection. Parameter: [search] Parameter Type: [POSTPARAM] Detection Method: [Single Quote/Two Single Quote, Code Change (200->500->200)]"
                    in e.data["description"]
                ):
                    sqli_finding_emitted = True

        assert web_parameter_emitted, "WEB_PARAMETER was not emitted"
        assert not sqli_finding_emitted, "post-based SQLI emitted despite post-parameters being disabled"


# SQLI Single Quote/Two Single Quote (headers)
class Test_Lightfuzz_sqli_headers(Test_Lightfuzz_sqli):
    async def setup_after_prep(self, module_test):
        module_test.scan.modules["lightfuzz"].helpers.rand_string = lambda *args, **kwargs: "AAAAAAAAAAAAAA"
        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

        seed_events = []
        parent_event = module_test.scan.make_event(
            "http://127.0.0.1:8888/",
            "URL",
            module_test.scan.root_event,
            module="httpx",
            tags=["status-200", "distance-0"],
        )

        data = {
            "host": "127.0.0.1",
            "type": "HEADER",
            "name": "testheader",
            "original_value": None,
            "url": "http://127.0.0.1:8888",
            "description": "Test Dummy Header",
        }
        seed_event = module_test.scan.make_event(data, "WEB_PARAMETER", parent_event, tags=["distance-0"])
        seed_events.append(seed_event)
        for event in seed_events:
            await module_test.scan.ingress_module.incoming_event_queue.put(event)

    def request_handler(self, request):
        placeholder_block = """
        <html>
        <p>placeholder</p>
        </html>
        """

        if request.headers.get("testheader") is not None:
            header_value = request.headers.get("testheader")

            header_block_normal = f"""
            <html>
            <p>placeholder</p>
            <p>test: {header_value}</p>
            </html>
            """
            header_block_error = """
            <html>
            <p>placeholder</p>
            <p>Error!</p>
            </html>
            """
            if header_value.endswith("'") and not header_value.endswith("''"):
                return Response(header_block_error, status=500)
            return Response(header_block_normal, status=200)
        return Response(placeholder_block, status=200)

    def check(self, module_test, events):
        sqli_finding_emitted = False
        for e in events:
            if e.type == "FINDING":
                if (
                    "Possible SQL Injection. Parameter: [testheader] Parameter Type: [HEADER] Detection Method: [Single Quote/Two Single Quote, Code Change (200->500->200)]"
                    in e.data["description"]
                ):
                    sqli_finding_emitted = True
        assert sqli_finding_emitted, "SQLi Single/Double Quote headers FINDING not emitted"


# SQLI Single Quote/Two Single Quote (cookies)
class Test_Lightfuzz_sqli_cookies(Test_Lightfuzz_sqli):
    async def setup_after_prep(self, module_test):
        module_test.scan.modules["lightfuzz"].helpers.rand_string = lambda *args, **kwargs: "AAAAAAAAAAAAAA"
        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

        seed_events = []
        parent_event = module_test.scan.make_event(
            "http://127.0.0.1:8888/",
            "URL",
            module_test.scan.root_event,
            module="httpx",
            tags=["status-200", "distance-0"],
        )

        data = {
            "host": "127.0.0.1",
            "type": "COOKIE",
            "name": "test",
            "original_value": None,
            "url": "http://127.0.0.1:8888",
            "description": "Test Dummy Cookie",
        }
        seed_event = module_test.scan.make_event(data, "WEB_PARAMETER", parent_event, tags=["distance-0"])
        seed_events.append(seed_event)
        for event in seed_events:
            await module_test.scan.ingress_module.incoming_event_queue.put(event)

    def request_handler(self, request):
        placeholder_block = """
        <html>
        <p>placeholder</p>
        </html>
        """

        if request.cookies.get("test") is not None:
            header_value = request.cookies.get("test")

            header_block_normal = f"""
            <html>
            <p>placeholder</p>
            <p>test: {header_value}</p>
            </html>
            """

            header_block_error = """
            <html>
            <p>placeholder</p>
            <p>Error!</p>
            </html>
            """
            if header_value.endswith("'") and not header_value.endswith("''"):
                return Response(header_block_error, status=500)
            return Response(header_block_normal, status=200)
        return Response(placeholder_block, status=200)

    def check(self, module_test, events):
        sqli_finding_emitted = False
        for e in events:
            if e.type == "FINDING":
                if (
                    "Possible SQL Injection. Parameter: [test] Parameter Type: [COOKIE] Detection Method: [Single Quote/Two Single Quote, Code Change (200->500->200)]"
                    in e.data["description"]
                ):
                    sqli_finding_emitted = True
        assert sqli_finding_emitted, "SQLi Single/Double Quote cookies FINDING not emitted"


# SQLi Delay Probe
class Test_Lightfuzz_sqli_delay(Test_Lightfuzz_sqli):
    def request_handler(self, request):
        from time import sleep

        qs = str(request.query_string.decode())

        parameter_block = """
        <section class=search>
            <form action=/ method=GET>
                <input type=text placeholder='Search the blog...' name=search>
                <button type=submit class=button>Search</button>
            </form>
        </section>

        """
        if "search=" in qs:
            value = qs.split("=")[1]

            if "&" in value:
                value = value.split("&")[0]

            sql_block = """
        <section class=blog-header>
            <h1>0 search results found</h1>
            <hr>
        </section>
        """
            if "' AND (SLEEP(5)) AND '" in unquote(value):
                sleep(5)
            return Response(sql_block, status=200)
        return Response(parameter_block, status=200)

    def check(self, module_test, events):
        web_parameter_emitted = False
        sqldelay_finding_emitted = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [search]" in e.data["description"]:
                    web_parameter_emitted = True

            if e.type == "FINDING":
                if (
                    "Possible Blind SQL Injection. Parameter: [search] Parameter Type: [GETPARAM] Detection Method: [Delay Probe (1' AND (SLEEP(5)) AND ')]"
                    in e.data["description"]
                ):
                    sqldelay_finding_emitted = True

        assert web_parameter_emitted, "WEB_PARAMETER was not emitted"
        assert sqldelay_finding_emitted, "SQLi Delay FINDING not emitted"


# Serialization Module (Error Resolution)
class Test_Lightfuzz_serial_errorresolution(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "lightfuzz", "excavate"]
    config_overrides = {
        "interactsh_disable": True,
        "modules": {
            "lightfuzz": {
                "enabled_submodules": ["serial"],
            }
        },
    }

    dotnet_serial_error = """
        <html>
        <b> Description: </b>An unhandled exception occurred during the execution of the current web request. Please review the stack trace for more information about the error and where it originated in the code.

        <br><br>

        <b> Exception Details: </b>System.Runtime.Serialization.SerializationException: End of Stream encountered before parsing was completed.<br><br>
        </html>
        """

    dotnet_serial_html = """
        <!DOCTYPE html>
        <html>
        <head><title>
            Deserialization RCE Example
        </title></head>
        <body>
            <form method="post" action="./deser.aspx" id="form1">
        <div class="aspNetHidden">
        <input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="/wEPDwULLTE5MTI4MzkxNjVkZNt7ICM+GixNryV6ucx+srzhXlwP" />
        </div>

        <div class="aspNetHidden">

            <input type="hidden" name="__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="AD6F025C" />
            <input type="hidden" name="__EVENTVALIDATION" id="__EVENTVALIDATION" value="/wEdAANdCjkiIFhjCB8ta8aO/EhuESCFkFW/RuhzY1oLb/NUVM34O/GfAV4V4n0wgFZHr3czZjft8VgObR/WUivai7w4kfR1wg==" />
        </div>
                <div>
                    <h2>Deserialization Test</h2>
                    <span id="Label1">Enter serialized data:</span><br />
                    <textarea name="TextBox1" rows="2" cols="20" id="TextBox1" style="height:100px;width:400px;">
        </textarea><br /><br />
                    <input type="submit" name="Button1" value="Submit" id="Button1" /><br /><br />
                </div>
            </form>

            
        </body>
        </html>
        """

    async def setup_after_prep(self, module_test):
        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

    def request_handler(self, request):
        dotnet_serial_error_resolved = (
            "<html><body>Deserialization successful! Object type: System.String</body></html>"
        )
        post_params = request.form

        if "TextBox1" not in post_params.keys():
            return Response(self.dotnet_serial_html, status=200)

        else:
            if post_params["__VIEWSTATE"] != "/wEPDwULLTE5MTI4MzkxNjVkZNt7ICM+GixNryV6ucx+srzhXlwP":
                return Response(self.dotnet_serial_error, status=500)
            if post_params["TextBox1"] == "AAEAAAD/////AQAAAAAAAAAGAQAAAAdndXN0YXZvCw==":
                return Response(dotnet_serial_error_resolved, status=200)
            else:
                return Response(self.dotnet_serial_error, status=500)

    def check(self, module_test, events):
        excavate_extracted_form_parameter = False
        excavate_extracted_form_parameter_details = False
        lightfuzz_serial_detect_errorresolution = False

        for e in events:
            if e.type == "WEB_PARAMETER":
                if e.data["name"] == "TextBox1":
                    excavate_extracted_form_parameter = True
                    if (
                        e.data["url"] == "http://127.0.0.1:8888/deser.aspx"
                        and e.data["host"] == "127.0.0.1"
                        and e.data["additional_params"]
                        == {
                            "__VIEWSTATE": "/wEPDwULLTE5MTI4MzkxNjVkZNt7ICM+GixNryV6ucx+srzhXlwP",
                            "__VIEWSTATEGENERATOR": "AD6F025C",
                            "__EVENTVALIDATION": "/wEdAANdCjkiIFhjCB8ta8aO/EhuESCFkFW/RuhzY1oLb/NUVM34O/GfAV4V4n0wgFZHr3czZjft8VgObR/WUivai7w4kfR1wg==",
                            "Button1": "Submit",
                        }
                    ):
                        excavate_extracted_form_parameter_details = True
            if e.type == "FINDING":
                if (
                    e.data["description"]
                    == "POSSIBLE Unsafe Deserialization. Parameter: [TextBox1] Parameter Type: [POSTPARAM] Technique: [Error Resolution (Baseline: [500]  -> Probe: [200] )] Serialization Payload: [dotnet_base64]"
                ):
                    lightfuzz_serial_detect_errorresolution = True

        assert excavate_extracted_form_parameter, "WEB_PARAMETER for POST form was not emitted"
        assert excavate_extracted_form_parameter_details, "WEB_PARAMETER for POST form did not have correct data"
        assert lightfuzz_serial_detect_errorresolution, (
            "Lightfuzz Serial module failed to detect ASP.NET error resolution based deserialization"
        )


# Serialization Module (Error Resolution False Positive)
class Test_Lightfuzz_serial_errorresolution_falsepositive(Test_Lightfuzz_serial_errorresolution):
    def request_handler(self, request):
        dotnet_serial_error_resolved_with_general_error = (
            "<html><body>Internal Server Error (invalid characters!)</body></html>"
        )
        post_params = request.form

        if "TextBox1" not in post_params.keys():
            return Response(self.dotnet_serial_html, status=200)

        else:
            if post_params["__VIEWSTATE"] != "/wEPDwULLTE5MTI4MzkxNjVkZNt7ICM+GixNryV6ucx+srzhXlwP":
                return Response(self.dotnet_serial_error, status=500)
            if post_params["TextBox1"] == "AAEAAAD/////AQAAAAAAAAAGAQAAAAdndXN0YXZvCw==":
                return Response(dotnet_serial_error_resolved_with_general_error, status=200)
            else:
                return Response(self.dotnet_serial_error, status=500)

    def check(self, module_test, events):
        no_finding_emitted = True

        for e in events:
            if e.type == "FINDING":
                no_finding_emitted = False

        assert no_finding_emitted, "False positive finding was emitted"


class Test_Lightfuzz_serial_errorresolution_existingvalue_valid(Test_Lightfuzz_serial_errorresolution):
    dotnet_serial_html = """
        <!DOCTYPE html>
        <html>
        <head><title>
            Deserialization RCE Example
        </title></head>
        <body>
            <form method="post" action="./deser.aspx" id="form1">
        <div class="aspNetHidden">
        <input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="/wEPDwULLTE5MTI4MzkxNjVkZNt7ICM+GixNryV6ucx+srzhXlwP" />
        </div>

        <div class="aspNetHidden">

            <input type="hidden" name="__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="AD6F025C" />
            <input type="hidden" name="__EVENTVALIDATION" id="__EVENTVALIDATION" value="/wEdAANdCjkiIFhjCB8ta8aO/EhuESCFkFW/RuhzY1oLb/NUVM34O/GfAV4V4n0wgFZHr3czZjft8VgObR/WUivai7w4kfR1wg==" />
        </div>
                <div>
                    <h2>Deserialization Test</h2>
                    <span id="Label1">Enter serialized data:</span><br />
                    <textarea name="TextBox1" rows="2" cols="20" id="TextBox1" value="AAEAAAD/////AQAAAAAAAAAGAQAAAAdndXN0YXZvCw==" style="height:100px;width:400px;">
        </textarea><br /><br />
                    <input type="submit" name="Button1" value="Submit" id="Button1" /><br /><br />
                </div>
            </form>

            
        </body>
        </html>
        """

    def check(self, module_test, events):
        excavate_extracted_form_parameter = False
        excavate_extracted_form_parameter_details = False
        excavate_detect_serialization_value = False
        lightfuzz_serial_detect_errorresolution = False

        for e in events:
            if e.type == "WEB_PARAMETER":
                if e.data["name"] == "TextBox1":
                    excavate_extracted_form_parameter = True
                    if (
                        e.data["url"] == "http://127.0.0.1:8888/deser.aspx"
                        and e.data["host"] == "127.0.0.1"
                        and e.data["original_value"] == "AAEAAAD/////AQAAAAAAAAAGAQAAAAdndXN0YXZvCw=="
                        and e.data["additional_params"]
                        == {
                            "__VIEWSTATE": "/wEPDwULLTE5MTI4MzkxNjVkZNt7ICM+GixNryV6ucx+srzhXlwP",
                            "__VIEWSTATEGENERATOR": "AD6F025C",
                            "__EVENTVALIDATION": "/wEdAANdCjkiIFhjCB8ta8aO/EhuESCFkFW/RuhzY1oLb/NUVM34O/GfAV4V4n0wgFZHr3czZjft8VgObR/WUivai7w4kfR1wg==",
                            "Button1": "Submit",
                        }
                    ):
                        excavate_extracted_form_parameter_details = True
            if e.type == "FINDING":
                if e.data["description"] == "HTTP response (body) contains a possible serialized object (DOTNET)":
                    excavate_detect_serialization_value = True
                if (
                    e.data["description"]
                    == "POSSIBLE Unsafe Deserialization. Parameter: [TextBox1] Parameter Type: [POSTPARAM] Original Value: [AAEAAAD/////AQAAAAAAAAAGAQAAAAdndXN0YXZvCw==] Technique: [Error Resolution (Baseline: [500]  -> Probe: [200] )] Serialization Payload: [dotnet_base64]"
                ):
                    lightfuzz_serial_detect_errorresolution = True

        assert excavate_extracted_form_parameter, "WEB_PARAMETER for POST form was not emitted"
        assert excavate_extracted_form_parameter_details, "WEB_PARAMETER for POST form did not have correct data"
        assert excavate_detect_serialization_value, "WEB_PARAMETER for POST form did not have correct data"
        assert lightfuzz_serial_detect_errorresolution, (
            "Lightfuzz Serial module failed to detect ASP.NET error resolution based deserialization"
        )


class Test_Lightfuzz_serial_errorresolution_existingvalue_invalid(Test_Lightfuzz_serial_errorresolution_falsepositive):
    dotnet_serial_html = """
        <!DOCTYPE html>
        <html>
        <head><title>
            Deserialization RCE Example
        </title></head>
        <body>
            <form method="post" action="./deser.aspx" id="form1">
        <div class="aspNetHidden">
        <input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="/wEPDwULLTE5MTI4MzkxNjVkZNt7ICM+GixNryV6ucx+srzhXlwP" />
        </div>

        <div class="aspNetHidden">

            <input type="hidden" name="__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="AD6F025C" />
            <input type="hidden" name="__EVENTVALIDATION" id="__EVENTVALIDATION" value="/wEdAANdCjkiIFhjCB8ta8aO/EhuESCFkFW/RuhzY1oLb/NUVM34O/GfAV4V4n0wgFZHr3czZjft8VgObR/WUivai7w4kfR1wg==" />
        </div>
                <div>
                    <h2>Deserialization Test</h2>
                    <span id="Label1">Enter serialized data:</span><br />
                    <textarea name="TextBox1" rows="2" cols="20" id="TextBox1" value="not_valid_base64!" style="height:100px;width:400px;">
        </textarea><br /><br />
                    <input type="submit" name="Button1" value="Submit" id="Button1" /><br /><br />
                </div>
            </form>

            
        </body>
        </html>
        """


# Serialization Module (Error Differential)
class Test_Lightfuzz_serial_errordifferential(Test_Lightfuzz_serial_errorresolution):
    def request_handler(self, request):
        java_serial_error = """
            <html>
                   <h4>Internal Server Error</h4>
                    <p class=is-warning>java.io.StreamCorruptedException: invalid stream header: 0C400304</p>
            </html>
            """

        java_serial_error_keyword = """
        <html>
                    <h4>Internal Server Error</h4>
                    <p class=is-warning>java.lang.ClassCastException: Cannot cast java.lang.String to lab.actions.common.serializable.AccessTokenUser</p>
        </html>
        """

        java_serial_html = """
        <!DOCTYPE html>
        <html>
        <head><title>
            Deserialization RCE Example
        </title></head>
        <body>
            Please log in to continue.
        </body>
        </html>
        """

        cookies = request.cookies

        if "session" not in cookies.keys():
            response = Response(java_serial_html, status=200)
            response.set_cookie("session", value="", max_age=3600, httponly=True)
            return response

        else:
            if unquote(cookies["session"]) == "rO0ABXQABHRlc3Q=":
                return Response(java_serial_error_keyword, status=500)
            else:
                return Response(java_serial_error, status=500)

    def check(self, module_test, events):
        excavate_extracted_cookie_parameter = False
        lightfuzz_serial_detect_errordifferential = False

        for e in events:
            if e.type == "WEB_PARAMETER":
                if e.data["description"] == "Set-Cookie Assigned Cookie [session]" and e.data["type"] == "COOKIE":
                    excavate_extracted_cookie_parameter = True

            if e.type == "FINDING":
                if (
                    e.data["description"]
                    == "POSSIBLE Unsafe Deserialization. Parameter: [session] Parameter Type: [COOKIE] Technique: [Differential Error Analysis] Error-String: [cannot cast java.lang.string] Payload: [java_base64_string_error]"
                ):
                    lightfuzz_serial_detect_errordifferential = True

        assert excavate_extracted_cookie_parameter, "WEB_PARAMETER for cookie was not emitted"
        assert lightfuzz_serial_detect_errordifferential, (
            "Lightfuzz Serial module failed to detect Java error differential based deserialization"
        )


# Serialization Modules (Error Differential - False positive check)
class Test_Lightfuzz_serial_errordifferential_falsepositive(Test_Lightfuzz_serial_errorresolution):
    def request_handler(self, request):
        post_params = request.form
        if "TextBox1" not in post_params.keys():
            return Response(self.dotnet_serial_html, status=200)

        else:
            dotnet_serial_reflection = (
                f"<html><body><p>invalid user</p><p>reflected input: {post_params['TextBox1']}</body></html>"
            )
            return Response(dotnet_serial_reflection, status=500)

    def check(self, module_test, events):
        finding_count = 0
        for e in events:
            if e.type == "FINDING":
                finding_count += 1
        assert finding_count == 0, "Unexpected FINDING events reported"


# CMDi echo canary
class Test_Lightfuzz_cmdi(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "lightfuzz", "excavate"]
    config_overrides = {
        "interactsh_disable": True,
        "modules": {
            "lightfuzz": {
                "enabled_submodules": ["cmdi"],
            }
        },
    }

    def request_handler(self, request):
        qs = str(request.query_string.decode())

        parameter_block = """
        <section class=search>
            <form action=/ method=GET>
                <input type=text placeholder='Search the blog...' name=search>
                <button type=submit class=button>Search</button>
            </form>
        </section>
        """
        if "search=" in qs:
            value = qs.split("=")[1]
            if "&" in value:
                value = value.split("&")[0]
            if "&& echo " in unquote(value):
                cmdi_value = unquote(value).split("&& echo ")[1].split(" ")[0]
            else:
                cmdi_value = value
            cmdi_block = f"""
        <section class=blog-header>
            <h1>0 search results for '{unquote(cmdi_value)}'</h1>
            <hr>
        </section>
        """
            return Response(cmdi_block, status=200)

        return Response(parameter_block, status=200)

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["lightfuzz"].helpers.rand_string = lambda *args, **kwargs: "AAAAAAAAAAAAAA"
        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

    def check(self, module_test, events):
        web_parameter_emitted = False
        cmdi_echocanary_finding_emitted = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [search]" in e.data["description"]:
                    web_parameter_emitted = True

            if e.type == "FINDING":
                if (
                    "POSSIBLE OS Command Injection. Parameter: [search] Parameter Type: [GETPARAM] Detection Method: [echo canary] CMD Probe Delimeters: [&&]"
                    in e.data["description"]
                ):
                    cmdi_echocanary_finding_emitted = True

        assert web_parameter_emitted, "WEB_PARAMETER was not emitted"
        assert cmdi_echocanary_finding_emitted, "echo canary CMDi FINDING not emitted"


# CMDi interactsh
class Test_Lightfuzz_cmdi_interactsh(Test_Lightfuzz_cmdi):
    @staticmethod
    def extract_subdomain_tag(data):
        pattern = r"search=.+%26%26%20nslookup%20(.+)\.fakedomain\.fakeinteractsh.com%20%26%26"
        match = re.search(pattern, data)
        if match:
            return match.group(1)

    config_overrides = {
        "interactsh_disable": False,
        "modules": {
            "lightfuzz": {
                "enabled_submodules": ["cmdi"],
            }
        },
    }

    def request_handler(self, request):
        qs = str(request.query_string.decode())

        parameter_block = """
        <section class=search>
            <form action=/ method=GET>
                <input type=text placeholder='Search the blog...' name=search>
                <button type=submit class=button>Search</button>
            </form>
        </section>
        """

        if "search=" in qs:
            subdomain_tag = None
            subdomain_tag = self.extract_subdomain_tag(request.full_path)

            if subdomain_tag:
                self.interactsh_mock_instance.mock_interaction(subdomain_tag)
        return Response(parameter_block, status=200)

    async def setup_before_prep(self, module_test):
        self.interactsh_mock_instance = module_test.mock_interactsh("lightfuzz")

        module_test.monkeypatch.setattr(
            module_test.scan.helpers, "interactsh", lambda *args, **kwargs: self.interactsh_mock_instance
        )

    async def setup_after_prep(self, module_test):
        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

    def check(self, module_test, events):
        web_parameter_emitted = False
        cmdi_interacttsh_finding_emitted = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [search]" in e.data["description"]:
                    web_parameter_emitted = True

            if e.type == "VULNERABILITY":
                if (
                    "OS Command Injection (OOB Interaction) Type: [GETPARAM] Parameter Name: [search] Probe: [&&]"
                    in e.data["description"]
                ):
                    cmdi_interacttsh_finding_emitted = True

        assert web_parameter_emitted, "WEB_PARAMETER was not emitted"
        assert cmdi_interacttsh_finding_emitted, "interactsh CMDi FINDING not emitted"


class Test_Lightfuzz_speculative(ModuleTestBase):
    targets = ["http://127.0.0.1:8888/"]
    modules_overrides = ["httpx", "excavate", "paramminer_getparams", "lightfuzz"]
    config_overrides = {
        "interactsh_disable": True,
        "modules": {
            "lightfuzz": {"enabled_submodules": ["xss"]},
            "paramminer_getparams": {"wordlist": tempwordlist([]), "recycle_words": True},
            "excavate": {"speculate_params": True},
        },
    }

    def request_handler(self, request):
        qs = str(request.query_string.decode())
        parameter_block = """
        {
          "search": 1,
          "common": 1
        }
        """
        if "search=" in qs:
            value = qs.split("=")[1]
            if "&" in value:
                value = value.split("&")[0]
            xss_block = f"""
        <section class=blog-header>
            <h1>0 search results for '{unquote(value)}'</h1>
            <hr>
        </section>
        """
            return Response(xss_block, status=200)
        return Response(parameter_block, status=200, headers={"Content-Type": "application/json"})

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["lightfuzz"].helpers.rand_string = lambda *args, **kwargs: "AAAAAAAAAAAAAA"
        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

    def check(self, module_test, events):
        excavate_json_extraction = False
        xss_finding_emitted = False

        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter (speculative from json content) [search]" in e.data["description"]:
                    excavate_json_extraction = True

            if e.type == "FINDING":
                if "Possible Reflected XSS. Parameter: [search] Context: [Between Tags" in e.data["description"]:
                    xss_finding_emitted = True

        assert excavate_json_extraction, "Excavate failed to extract json parameter"
        assert xss_finding_emitted, "Between Tags XSS FINDING not emitted"


class Test_Lightfuzz_crypto_error(ModuleTestBase):
    targets = ["http://127.0.0.1:8888/"]
    modules_overrides = ["httpx", "excavate", "lightfuzz"]
    config_overrides = {
        "interactsh_disable": True,
        "modules": {
            "lightfuzz": {"enabled_submodules": ["crypto"]},
        },
    }

    def request_handler(self, request):
        qs = str(request.query_string.decode())

        parameter_block = """
        <section class=secret>
            <form action=/ method=GET>
                <input type=text value='08a5a2cea9c5a5576e6e5314edcba581d21c7111c9c0c06990327b9127058d67' name=secret>
                <button type=submit class=button>Secret Submit</button>
            </form>
        </section>
        """
        crypto_block = """
        <section class=blog-header>
            <h1>Access Denied!</h1>
            <hr>
        </section>
        """
        if "secret=" in qs:
            value = qs.split("=")[1]
            if value:
                return Response(crypto_block, status=200)

        return Response(parameter_block, status=200)

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["lightfuzz"].helpers.rand_string = lambda *args, **kwargs: "AAAAAAAAAAAAAA"
        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

    def check(self, module_test, events):
        cryptoerror_parameter_extracted = False
        cryptoerror_finding_emitted = False

        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [secret] (GET Form Submodule)" in e.data["description"]:
                    cryptoerror_parameter_extracted = True
            if e.type == "FINDING":
                if (
                    "Possible Cryptographic Error. Parameter: [secret] Parameter Type: [GETPARAM] Original Value: [08a5a2cea9c5a5576e6e5314edcba581d21c7111c9c0c06990327b9127058d67]"
                    in e.data["description"]
                ):
                    cryptoerror_finding_emitted = True
        assert cryptoerror_parameter_extracted, "Parameter not extracted"
        assert cryptoerror_finding_emitted, "Crypto Error Message FINDING not emitted"


class Test_Lightfuzz_crypto_error_falsepositive(ModuleTestBase):
    targets = ["http://127.0.0.1:8888/"]
    modules_overrides = ["httpx", "excavate", "lightfuzz"]
    config_overrides = {
        "interactsh_disable": True,
        "modules": {
            "lightfuzz": {"enabled_submodules": ["crypto"]},
        },
    }

    def request_handler(self, request):
        fp_block = """
        <section class=secret>
            <form action=/ method=GET>
                <input type=text value='08a5a2cea9c5a5576e6e5314edcba581d21c7111c9c0c06990327b9127058d67' name=secret>
                <button type=submit class=button>Secret Submit</button>
            </form>
            <h1>Access Denied!</h1>
        </section>
        """
        return Response(fp_block, status=200)

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["lightfuzz"].helpers.rand_string = lambda *args, **kwargs: "AAAAAAAAAAAAAA"
        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

    def check(self, module_test, events):
        cryptoerror_parameter_extracted = False
        cryptoerror_finding_emitted = False

        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [secret] (GET Form Submodule)" in e.data["description"]:
                    cryptoerror_parameter_extracted = True
            if e.type == "FINDING":
                if "Possible Cryptographic Error" in e.data["description"]:
                    cryptoerror_finding_emitted = True
        assert cryptoerror_parameter_extracted, "Parameter not extracted"
        assert not cryptoerror_finding_emitted, (
            "Crypto Error Message FINDING was emitted (it is an intentional false positive)"
        )


class Test_Lightfuzz_PaddingOracleDetection(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "excavate", "lightfuzz"]
    config_overrides = {
        "interactsh_disable": True,
        "modules": {
            "lightfuzz": {
                "enabled_submodules": ["crypto"],
            }
        },
    }

    def request_handler(self, request):
        encrypted_value = quote(
            "dplyorsu8VUriMW/8DqVDU6kRwL/FDk3Q+4GXVGZbo0CTh9YX1YvzZZJrYe4cHxvAICyliYtp1im4fWoOa54Zg=="
        )
        default_html_response = f"""
        <html>
            <body>
                <form action="/decrypt" method="post">
                    <input type="hidden" name="encrypted_data" value="{encrypted_value}" />
                    <button type="submit">Decrypt</button>
                </form>
            </body>
        </html>
        """

        if "/decrypt" in request.url and request.method == "POST":
            if request.form and request.form["encrypted_data"]:
                encrypted_data = request.form["encrypted_data"]
                if "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALwAgLKWJi2nWKbh9ag5rnhm" in encrypted_data:
                    response_content = "Padding error detected"
                elif "4GXVGZbo0DTh9YX1YvzZZJrYe4cHxvAICyliYtp1im4fWoOa54Zg" in encrypted_data:
                    response_content = "DIFFERENT CRYPTOGRAPHIC ERROR"
                elif "AAAAAAA" in encrypted_data:
                    response_content = "YET DIFFERENT CRYPTOGRAPHIC ERROR"
                else:
                    response_content = "Decryption failed"

            return Response(response_content, status=200)
        else:
            return Response(default_html_response, status=200)

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests_handler(expect_args=re.compile(".*"), request_handler=self.request_handler)

    def check(self, module_test, events):
        web_parameter_extracted = False
        cryptographic_parameter_finding = False
        padding_oracle_detected = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [encrypted_data] (POST Form" in e.data["description"]:
                    web_parameter_extracted = True
            if e.type == "FINDING":
                if (
                    e.data["description"]
                    == "Probable Cryptographic Parameter. Parameter: [encrypted_data] Parameter Type: [POSTPARAM] Original Value: [dplyorsu8VUriMW/8DqVDU6kRwL/FDk3Q%2B4GXVGZbo0CTh9YX1YvzZZJrYe4cHxvAICyliYtp1im4fWoOa54Zg%3D%3D] Detection Technique(s): [Single-byte Mutation] Envelopes: [URL-Encoded]"
                ):
                    cryptographic_parameter_finding = True

            if e.type == "VULNERABILITY":
                if (
                    e.data["description"]
                    == "Padding Oracle Vulnerability. Block size: [16] Parameter: [encrypted_data] Parameter Type: [POSTPARAM] Original Value: [dplyorsu8VUriMW/8DqVDU6kRwL/FDk3Q%2B4GXVGZbo0CTh9YX1YvzZZJrYe4cHxvAICyliYtp1im4fWoOa54Zg%3D%3D] Envelopes: [URL-Encoded]"
                ):
                    padding_oracle_detected = True

        assert web_parameter_extracted, "Web parameter was not extracted"
        assert cryptographic_parameter_finding, "Cryptographic parameter not detected"
        assert padding_oracle_detected, "Padding oracle vulnerability was not detected"


class Test_Lightfuzz_XSS_jsquotecontext(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "lightfuzz", "excavate", "paramminer_getparams"]
    config_overrides = {
        "interactsh_disable": True,
        "modules": {
            "lightfuzz": {"enabled_submodules": ["xss"]},
            "paramminer_getparams": {"wordlist": tempwordlist(["junk", "input"]), "recycle_words": True},
        },
    }

    def request_handler(self, request):
        # Decode the query string
        qs = str(request.query_string.decode())
        default_output = """
        <html>
            <form action="/" method="get">
                <input type="text" name="input" value="default">
                <input type="submit" value="Submit">
            </form>
        </html>
        """

        if "input=" in qs:
            # Split the query string to isolate the 'input' parameter
            params = qs.split("&")
            input_value = None
            for param in params:
                if param.startswith("input="):
                    input_value = param.split("=")[1]
                    break

            if input_value:
                # Simulate flawed escaping
                sanitized_input = input_value.replace('"', '\\"').replace("'", "\\'")
                sanitized_input = sanitized_input.replace("<", "%3C").replace(">", "%3E")

                # Construct the reflected block with the sanitized input
                reflected_block = f"""
                <html>
                    <script>
                        let userInput = '{sanitized_input}';
                        console.log(userInput);
                    </script>
                </html>
                """
                return Response(reflected_block, status=200)

        return Response(default_output, status=200)

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["paramminer_getparams"].rand_string = lambda *args, **kwargs: "AAAAAAAAAAAAAA"
        module_test.monkeypatch.setattr(
            helper.HttpCompare, "gen_cache_buster", lambda *args, **kwargs: {"AAAAAA": "1"}
        )
        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

    def check(self, module_test, events):
        web_parameter_emitted = False
        xss_finding_emitted = False

        for e in events:
            if e.type == "WEB_PARAMETER":
                if "[Paramminer] Getparam: [input] Reasons: [body] Reflection: [True]" in e.data["description"]:
                    web_parameter_emitted = True

            if e.type == "FINDING":
                if "Possible Reflected XSS. Parameter: [input] Context: [In Javascript (escaping the escape character, single quote)] Parameter Type: [GETPARAM]":
                    xss_finding_emitted = True

        assert web_parameter_emitted, "WEB_PARAMETER for was not emitted"
        assert xss_finding_emitted, "XSS FINDING not emitted"


class Test_Lightfuzz_XSS_jsquotecontext_doublequote(Test_Lightfuzz_XSS_jsquotecontext):
    def request_handler(self, request):
        qs = str(request.query_string.decode())
        default_output = """
        <html>
            <form action="/" method="get">
                <input type="text" name="input" value="default">
                <input type="submit" value="Submit">
            </form>
        </html>
        """

        if "input=" in qs:
            params = qs.split("&")
            input_value = None
            for param in params:
                if param.startswith("input="):
                    input_value = param.split("=")[1]
                    break

            if input_value:
                # Simulate flawed escaping with opposite quotes
                sanitized_input = input_value.replace("'", "\\").replace("%22", '\\"')
                sanitized_input = sanitized_input.replace("<", "%3C").replace(">", "%3E")

                reflected_block = f"""
                <html>
                    <script>
                        let userInput = "{sanitized_input}";
                        console.log(userInput);
                    </script>
                </html>
                """
                return Response(reflected_block, status=200)

        return Response(default_output, status=200)

    def check(self, module_test, events):
        web_parameter_emitted = False
        xss_finding_emitted = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if "[Paramminer] Getparam: [input] Reasons: [body] Reflection: [True]" in e.data["description"]:
                    web_parameter_emitted = True

            if e.type == "FINDING":
                if "Possible Reflected XSS. Parameter: [input] Context: [In Javascript (escaping the escape character, double quote)] Parameter Type: [GETPARAM]":
                    xss_finding_emitted = True

        assert web_parameter_emitted, "WEB_PARAMETER for was not emitted"
        assert xss_finding_emitted, "XSS FINDING not emitted"
