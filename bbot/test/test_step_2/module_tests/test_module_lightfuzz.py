import re

from .base import ModuleTestBase
from werkzeug.wrappers import Response
from urllib.parse import unquote


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

            block = f"""
<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1">
  <rect width="1" height="1" fill="black"/>
</svg>
        """
            if value == "%2F.%2Fdefault.jpg" or value == "default.jpg":
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
                    "POSSIBLE Path Traversal. Parameter: [filename] Parameter Type: [GETPARAM] Detection Method: [single-dot traversal tolerance"
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
                    "POSSIBLE Path Traversal. Parameter: [filename] Parameter Type: [GETPARAM] Detection Method: [Absolute Path: /etc/passwd]"
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
        respond_args = {"response_data": "", "status": 302, "headers": {"Location": "/test?data=1"}}
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
                    "POSSIBLE Server-side Template Injection. Parameter: [data] Parameter Type: [GETPARAM] Detection Method: [Integer Multiplication]"
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
                if "Possible Reflected XSS. Parameter: [search] Context: [Between Tags]" in e.data["description"]:
                    xss_finding_emitted = True

        assert web_parameter_emitted, "WEB_PARAMETER was not emitted"
        assert xss_finding_emitted, "Between Tags XSS FINDING not emitted"


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
    def request_handler(self, request):
        qs = str(request.query_string.decode())
        parameter_block = """
        <html>
            <a href="/otherpage.php?language=en">Link</a>
        </html>
        """
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
        print("((((")
        print(request)
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

            sql_block_error = f"""
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
                    "Possible SQL Injection. Parameter: [search] Parameter Type: [GETPARAM] Detection Method: [Single Quote/Two Single Quote]"
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

        qs = str(request.query_string.decode())

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

            sql_block_error = f"""
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
                    "Possible SQL Injection. Parameter: [search] Parameter Type: [POSTPARAM] Detection Method: [Single Quote/Two Single Quote]"
                    in e.data["description"]
                ):
                    sqli_finding_emitted = True

        assert web_parameter_emitted, "WEB_PARAMETER was not emitted"
        assert sqli_finding_emitted, "SQLi Single/Double Quote postparam FINDING not emitted"


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
            "name": "test",
            "original_value": None,
            "url": "http://127.0.0.1:8888",
            "description": "Test Dummy Header",
        }
        seed_event = module_test.scan.make_event(data, "WEB_PARAMETER", parent_event, tags=["distance-0"])
        seed_events.append(seed_event)
        module_test.scan.target.seeds._events = set(seed_events)

    def request_handler(self, request):

        placeholder_block = """
        <html>
        <p>placeholder</p>
        </html>
        """

        qs = str(request.query_string.decode())
        if request.headers.get("Test") is not None:
            header_value = request.headers.get("Test")

            header_block_normal = f"""
            <html>
            <p>placeholder</p>
            <p>test: {header_value}</p>
            </html>
            """
            header_block_error = f"""
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

        web_parameter_emitted = False
        sqli_finding_emitted = False
        for e in events:
            if e.type == "FINDING":
                if (
                    "Possible SQL Injection. Parameter: [test] Parameter Type: [HEADER] Detection Method: [Single Quote/Two Single Quote]"
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
            "description": "Test Dummy Header",
        }
        seed_event = module_test.scan.make_event(data, "WEB_PARAMETER", parent_event, tags=["distance-0"])
        seed_events.append(seed_event)
        module_test.scan.target.seeds._events = set(seed_events)

    def request_handler(self, request):

        placeholder_block = """
        <html>
        <p>placeholder</p>
        </html>
        """

        qs = str(request.query_string.decode())
        if request.cookies.get("test") is not None:
            header_value = request.cookies.get("test")

            header_block_normal = f"""
            <html>
            <p>placeholder</p>
            <p>test: {header_value}</p>
            </html>
            """

            header_block_error = f"""
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

        web_parameter_emitted = False
        sqli_finding_emitted = False
        for e in events:
            if e.type == "FINDING":
                if (
                    "Possible SQL Injection. Parameter: [test] Parameter Type: [COOKIE] Detection Method: [Single Quote/Two Single Quote]"
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

            sql_block = f"""
        <section class=blog-header>
            <h1>0 search results found</h1>
            <hr>
        </section>
        """
            if "'%20AND%20(SLEEP(5))%20AND%20" in value:
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

            if "%26%26%20echo%20" in value:
                cmdi_value = value.split("%26%26%20echo%20")[1].split("%20")[0]
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
            value = qs.split("=")[1]

            if "&" in value:
                value = value.split("&")[0]

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
