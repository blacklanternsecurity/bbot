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
    modules_overrides = ["http", "lightfuzz", "excavate"]
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
            # Real path-traversal payload: a successful fetch of a different
            # resource (200 + distinct body). This is what a vulnerable server
            # actually returns — it's the signal the detector relies on.
            traversed_block = """
<svg xmlns="http://www.w3.org/2000/svg" width="2" height="2">
  <rect width="2" height="2" fill="red"/>
</svg>
SECRET_FROM_PARENT_DIR
        """
            if value == "%2F.%2Fa%2F..%2Fdefault.jpg" or value == "default.jpg":
                return Response(block, status=200)
            if value == "%2F..%2Fa%2F..%2Fdefault.jpg":
                return Response(traversed_block, status=200)
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


# Path Traversal single-dot tolerance, strict path resolver (Python/Go/Rust style)
# Simulates a server that opens files via a raw OS path walk rather than by
# string-normalizing first (as PHP include() does). Only the "simple" dot probes
# — `./X` and `/./X` — resolve cleanly; the `a/../X` variants fail on the missing
# `a/` component. Guards against regression of the simple-probe coverage path
# that was previously missed on non-PHP stacks.
class Test_Lightfuzz_path_singledot_strict(Test_Lightfuzz_path_singledot):
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
            # Real strict-resolver traversal: `../X` reads a different file
            # successfully (200 + distinct body). The detector requires a
            # successful fetch on the doubledot probe to flag.
            traversed_block = """
<svg xmlns="http://www.w3.org/2000/svg" width="2" height="2">
  <rect width="2" height="2" fill="red"/>
</svg>
SECRET_FROM_PARENT_DIR
        """
            # Only exact-file or simple-dot-prefixed reads succeed. Any path
            # containing `a/../` fails because `a/` does not exist, mirroring
            # Python's open() / Go's os.Open behavior on the filesystem.
            if value in (
                "default.jpg",
                "./default.jpg",
                "/./default.jpg",
                "%2E%2Fdefault.jpg",
            ):
                return Response(block, status=200)
            if value == "../default.jpg":
                return Response(traversed_block, status=200)
        return Response("file not found", status=500)

    def check(self, module_test, events):
        web_parameter_emitted = False
        simple_pathtraversal_finding_emitted = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [filename]" in e.data["description"]:
                    web_parameter_emitted = True

            if e.type == "FINDING":
                desc = e.data["description"]
                if (
                    "POSSIBLE Path Traversal" in desc
                    and "Parameter: [filename]" in desc
                    and "single-dot traversal tolerance (simple" in desc
                ):
                    simple_pathtraversal_finding_emitted = True

        assert web_parameter_emitted, "WEB_PARAMETER was not emitted"
        assert simple_pathtraversal_finding_emitted, (
            "Simple single-dot path traversal FINDING not emitted — strict-resolver detection regression."
        )


# Negative regression test for the JSF-style path-traversal FP: a server
# that normalizes `./X` (returns the canonical resource for the no-op
# prefix) but strictly REJECTS any `..` segment with a 4xx/empty body.
# That's the opposite of a vulnerability — no file from a different path
# is being delivered. The detector must not emit a finding.
class Test_Lightfuzz_path_singledot_rejection_fp(Test_Lightfuzz_path_singledot):
    def request_handler(self, request):
        qs = str(request.query_string.decode())
        if "filename=" in qs:
            value = qs.split("=")[1]
            if "&" in value:
                value = value.split("&")[0]

            # Strict rejection of any `..` segment in any encoding (raw,
            # url-encoded, double-url-encoded). Empty body — no resource
            # exfiltrated.
            decoded = unquote(unquote(value))
            if ".." in decoded:
                return Response("", status=404)

            block = """
<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1">
  <rect width="1" height="1" fill="black"/>
</svg>
        """
            # Server normalizes `./` (and url-encoded variants) to a no-op
            # and returns the canonical resource — singledot tolerance only.
            if "default.jpg" in decoded:
                return Response(block, status=200)
        return Response("", status=404)

    def check(self, module_test, events):
        for e in events:
            if e.type == "FINDING":
                desc = e.data["description"]
                assert "Possible Path Traversal" not in desc and "POSSIBLE Path Traversal" not in desc, (
                    f"Path Traversal false positive emitted when server rejects `..`: {desc}"
                )


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
    modules_overrides = ["http", "lightfuzz", "excavate"]
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


# SSTI direct {{A*B}} probe — simulates a template engine (e.g. Jinja2 with
# StrictUndefined) that raises on `{{undefined_var}}` so the comma-collapse
# trick fails, but still evaluates an arithmetic expression like
# `{{1337*1337}}` because arithmetic has no undefined variables.
class Test_Lightfuzz_ssti_direct_jinja(Test_Lightfuzz_ssti_multiply):
    def request_handler(self, request):
        qs = str(request.query_string.decode())
        from urllib.parse import unquote as _unquote

        value = qs.split("data=")[1] if "data=" in qs else ""
        if "&" in value:
            value = value.split("&")[0]
        decoded = _unquote(value)
        # `{{z}}` raises in StrictUndefined engines — the comma-collapse
        # probe produces a 500 instead of the expected `1,787,569`.
        if "{{z}}" in decoded:
            return Response("Template error: 'z' is undefined", status=500)
        # `{{A*B}}` evaluates normally when A and B are literal ints.
        if decoded.startswith("{{") and decoded.endswith("}}"):
            inner = decoded[2:-2]
            if "*" in inner:
                a, b = inner.split("*")
                try:
                    return Response(f"<html><div>{int(a) * int(b)}</div></html>", status=200)
                except ValueError:
                    pass
        # Anything else: baseline-ish echo, no template evaluation
        return Response(f"<html><div>Hi, {decoded}</div></html>", status=200)

    def check(self, module_test, events):
        ssti_finding = False
        for e in events:
            if e.type == "FINDING":
                desc = e.data["description"]
                if "Server-side Template Injection" in desc and "[{{1337*1337}}]" in desc:
                    ssti_finding = True
        assert ssti_finding, "Direct {{1337*1337}} SSTI FINDING not emitted"


# SSTI baseline FP suppression — simulates an endpoint whose static content
# happens to include the canary product value (1787569 or 1,787,569). The
# baseline check should suppress all ssti findings on this endpoint.
class Test_Lightfuzz_ssti_baseline_fp(Test_Lightfuzz_ssti_multiply):
    def request_handler(self, request):
        # Every response contains the canary literal as static content.
        # No template evaluation anywhere — pure coincidental number.
        return Response(
            "<html><body>Total units sold: 1,787,569</body></html>",
            status=200,
        )

    def check(self, module_test, events):
        ssti_finding = False
        for e in events:
            if e.type == "FINDING":
                if "Server-side Template Injection" in e.data.get("description", ""):
                    ssti_finding = True
        assert not ssti_finding, (
            "SSTI finding emitted on a page whose baseline already contains "
            "the canary number — baseline-check guard failed."
        )


# SSTI Apache Velocity — `#set($x=A*B)$x` syntax. None of the pre-existing
# probes use this shape so a Velocity-backed endpoint would slip past.
class Test_Lightfuzz_ssti_velocity(Test_Lightfuzz_ssti_multiply):
    def request_handler(self, request):
        qs = str(request.query_string.decode())
        from urllib.parse import unquote as _unquote

        value = qs.split("data=")[1] if "data=" in qs else ""
        if "&" in value:
            value = value.split("&")[0]
        decoded = _unquote(value)
        # Recognize a Velocity `#set($x=A*B)$x` probe and render the product.
        m = re.match(r"#set\(\$\w+=(\d+)\*(\d+)\)\$\w+", decoded)
        if m:
            return Response(
                f"<html><div>{int(m.group(1)) * int(m.group(2))}</div></html>",
                status=200,
            )
        # Anything else: plain echo with no template evaluation
        return Response(f"<html><div>Hi, {decoded}</div></html>", status=200)

    def check(self, module_test, events):
        velocity_finding = False
        for e in events:
            if e.type == "FINDING":
                desc = e.data["description"]
                if "Server-side Template Injection" in desc and "%23set" in desc:
                    velocity_finding = True
        assert velocity_finding, "Velocity SSTI FINDING not emitted"


# Between Tags XSS Detection
class Test_Lightfuzz_xss(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["http", "lightfuzz", "excavate"]
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
        module_test.scan.modules["lightfuzz"].helpers.rand_string = lambda *args, **kwargs: (
            "1234567890" if kwargs.get("numeric_only") else "AAAAAAAAAAAAAA"
        )
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


# Tag Attribute XSS with single-quoted value. Verifies that the attribute-
# context probes trigger against `<tag attr='...reflection...'>` — which was
# previously missed because the regex only matched double-quoted attributes
# and the breakout probe hardcoded `"` as the breakout char.
class Test_Lightfuzz_xss_single_quote_attribute(Test_Lightfuzz_xss):
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
            # Single-quoted attribute; only `<` and `>` are stripped so the
            # attacker can still close the quote and inject event handlers.
            safe = unquote(value).replace("<", "").replace(">", "")
            xss_block = f"""
        <section>
            <div data-user='{safe}'>hi</div>
            <hr>
        </section>
        """
            return Response(xss_block, status=200)
        return Response(parameter_block, status=200)

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["lightfuzz"].helpers.rand_string = lambda *args, **kwargs: (
            "1234567890" if kwargs.get("numeric_only") else "AAAAAAAAAAAAAA"
        )
        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)
        expect_args = re.compile("/otherpage.php")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

    def check(self, module_test, events):
        web_parameter_emitted = False
        single_quote_finding = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [foo]" in e.data["description"]:
                    web_parameter_emitted = True
            if e.type == "FINDING":
                desc = e.data["description"]
                if (
                    "Possible Reflected XSS" in desc
                    and "Parameter: [foo]" in desc
                    and "Tag Attribute (' quoted)" in desc
                ):
                    single_quote_finding = True

        assert web_parameter_emitted, "WEB_PARAMETER was not emitted"
        assert single_quote_finding, "Single-quote attribute XSS FINDING not emitted"


# HTML-comment-context XSS. Verifies that a reflection inside `<!-- ... -->`
# is detected when the `-->` sequence survives reflection (attacker can
# close the comment and inject markup afterward).
class Test_Lightfuzz_xss_html_comment(Test_Lightfuzz_xss):
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
            decoded = unquote(value)
            return Response(f"<html><body><!-- note: {decoded} --></body></html>", status=200)
        return Response(parameter_block, status=200)

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["lightfuzz"].helpers.rand_string = lambda *args, **kwargs: (
            "1234567890" if kwargs.get("numeric_only") else "AAAAAAAAAAAAAA"
        )
        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)
        expect_args = re.compile("/otherpage.php")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

    def check(self, module_test, events):
        html_comment_finding = False
        for e in events:
            if e.type == "FINDING":
                desc = e.data["description"]
                if "Possible Reflected XSS" in desc and "Context: [HTML Comment]" in desc:
                    html_comment_finding = True
        assert html_comment_finding, "HTML Comment XSS FINDING not emitted"


# JS-template-literal-context XSS. Verifies detection of reflection inside
# a backtick-wrapped string in a <script> block, where `${...}` interpolation
# is the exploitation vector.
class Test_Lightfuzz_xss_js_backtick(Test_Lightfuzz_xss):
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
            decoded = unquote(value)
            # Strip angle brackets to block classic </script> closure, but
            # leave `${`, `}`, and backtick alone.
            safe = decoded.replace("<", "").replace(">", "")
            return Response(
                f"<html><body><script>const g = `hi, {safe}`;console.log(g);</script></body></html>",
                status=200,
            )
        return Response(parameter_block, status=200)

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["lightfuzz"].helpers.rand_string = lambda *args, **kwargs: (
            "1234567890" if kwargs.get("numeric_only") else "AAAAAAAAAAAAAA"
        )
        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)
        expect_args = re.compile("/otherpage.php")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

    def check(self, module_test, events):
        backtick_finding = False
        for e in events:
            if e.type == "FINDING":
                desc = e.data["description"]
                if "Possible Reflected XSS" in desc and "Context: [JS Template Literal]" in desc:
                    backtick_finding = True
        assert backtick_finding, "JS Template Literal XSS FINDING not emitted"


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
                desc = e.data["description"]
                if (
                    'Possible Reflected XSS. Parameter: [func] Context: [URL-scheme Injection (" quoted)] Parameter Type: [POSTPARAM]'
                    in desc
                ):
                    xss_finding_emitted = True

        assert web_parameter_emitted, "WEB_PARAMETER was not emitted"
        assert xss_finding_emitted, "URL-scheme Injection XSS FINDING not emitted"


# Negative regression test for the FMCSA-style URL-scheme false positive:
# the parameter is reflected only into a non-URL-bearing attribute
# (`<input value="...">`), with `<`, `>`, `"` HTML-encoded everywhere else.
# `javascript:RAND` survives into the value attribute, but no browser will
# navigate to it from there. The URL-scheme Injection probe must NOT fire.
class Test_Lightfuzz_xss_url_scheme_value_attr_fp(Test_Lightfuzz_xss):
    def request_handler(self, request):
        qs = str(request.query_string.decode())
        parameter_block = """
        <html>
            <a href="/otherpage.php?Keyword=bar">Link</a>
        </html>
        """
        if "Keyword=" in qs:
            value = qs.split("=")[1]
            if "&" in value:
                value = value.split("&")[0]
            decoded = unquote(value)
            # Mimic the FMCSA pattern: `"`, `<`, `>` are HTML-encoded
            # outside the value attribute, and the only place the raw
            # token survives is inside `<input value="...">`.
            safe = decoded.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
            return Response(
                f"<html><body>"
                f"<title>{safe}</title>"
                f'<input id="Keyword" name="Keyword" value="{decoded}" />'
                f"</body></html>",
                status=200,
            )
        return Response(parameter_block, status=200)

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["lightfuzz"].helpers.rand_string = lambda *args, **kwargs: (
            "1234567890" if kwargs.get("numeric_only") else "AAAAAAAAAAAAAA"
        )
        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)
        expect_args = re.compile("/otherpage.php")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

    def check(self, module_test, events):
        for e in events:
            if e.type == "FINDING":
                desc = e.data["description"]
                assert "URL-scheme Injection" not in desc, (
                    f"URL-scheme Injection false positive emitted for non-URL-bearing attribute: {desc}"
                )


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
        module_test.scan.modules["lightfuzz"].helpers.rand_string = lambda *args, **kwargs: (
            "1234567890" if kwargs.get("numeric_only") else "AAAAAAAAAAAAAA"
        )
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
                desc = e.data["description"]
                if "Possible Reflected XSS. Parameter: [foo] Context: [Tag Attribute" in desc and "quoted)" in desc:
                    xss_finding_emitted = True

        assert web_parameter_emitted, "WEB_PARAMETER was not emitted"
        assert original_value_captured, "original_value not captured"
        assert xss_finding_emitted, "Tag Attribute XSS FINDING not emitted"


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
        module_test.scan.modules["lightfuzz"].helpers.rand_string = lambda *args, **kwargs: (
            "1234567890" if kwargs.get("numeric_only") else "AAAAAAAAAAAAAA"
        )
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
                "enabled_submodules": ["cmdi", "crypto", "path", "serial", "sqli", "ssti", "xss", "esi"],
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
    modules_overrides = ["http", "lightfuzz", "excavate"]
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
        module_test.scan.modules["lightfuzz"].helpers.rand_string = lambda *args, **kwargs: (
            "1234567890" if kwargs.get("numeric_only") else "AAAAAAAAAAAAAA"
        )
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
    modules_overrides = ["http", "lightfuzz", "excavate"]
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
        module_test.scan.modules["lightfuzz"].helpers.rand_string = lambda *args, **kwargs: (
            "1234567890" if kwargs.get("numeric_only") else "AAAAAAAAAAAAAA"
        )
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
        module_test.scan.modules["lightfuzz"].helpers.rand_string = lambda *args, **kwargs: (
            "1234567890" if kwargs.get("numeric_only") else "AAAAAAAAAAAAAA"
        )
        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

        seed_events = []
        parent_event = module_test.scan.make_event(
            "http://127.0.0.1:8888/",
            "URL",
            module_test.scan.root_event,
            module="http",
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
        module_test.scan.modules["lightfuzz"].helpers.rand_string = lambda *args, **kwargs: (
            "1234567890" if kwargs.get("numeric_only") else "AAAAAAAAAAAAAA"
        )
        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

        seed_events = []
        parent_event = module_test.scan.make_event(
            "http://127.0.0.1:8888/",
            "URL",
            module_test.scan.root_event,
            module="http",
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


# Blind SQLi where only row-independent one-shot SLEEP payloads trigger a delay.
# Simulates the common real-world case where the injected value does not match
# any row in the target table, causing row-scoped AND-based SLEEP payloads to
# short-circuit and never execute. Also guards against regression of a missing
# list comma that previously fused Oracle and MSSQL probes into one malformed
# concatenated string.
class Test_Lightfuzz_sqli_delay_or_rowindependent(Test_Lightfuzz_sqli):
    received_payloads = []

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
            decoded = unquote(value)
            self.__class__.received_payloads.append(decoded)

            sql_block = """
        <section class=blog-header>
            <h1>0 search results found</h1>
            <hr>
        </section>
        """
            # Only the one-shot row-independent MySQL payload triggers a delay.
            # The original AND-based mysql probe does not fire here, simulating
            # a context where the injected value does not match any row.
            if "OR SLEEP(5) IS NOT NULL LIMIT 1-- -" in decoded:
                sleep(5)
            return Response(sql_block, status=200)
        return Response(parameter_block, status=200)

    def check(self, module_test, events):
        web_parameter_emitted = False
        one_shot_delay_finding = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [search]" in e.data["description"]:
                    web_parameter_emitted = True
            if e.type == "FINDING":
                desc = e.data["description"]
                if "Possible Blind SQL Injection" in desc and "OR SLEEP(5) IS NOT NULL LIMIT 1-- -" in desc:
                    one_shot_delay_finding = True

        # Guard against regression of the missing-comma bug: Python string-literal
        # concatenation of adjacent list entries would produce a payload containing
        # both DBMS_LOCK.SLEEP and WAITFOR, which is never a valid single probe.
        garbled = [p for p in self.received_payloads if "DBMS_LOCK.SLEEP" in p and "WAITFOR" in p]
        assert not garbled, (
            f"Garbled Oracle+MSSQL concatenated probe was sent ({len(garbled)} times): "
            f"{garbled[:1]}. This indicates the missing-comma bug has regressed."
        )

        assert web_parameter_emitted, "WEB_PARAMETER was not emitted"
        assert one_shot_delay_finding, (
            "One-shot row-independent SLEEP finding not emitted — row-independent blind sqli detection regression."
        )


# Serialization Module (Error Resolution)
class Test_Lightfuzz_serial_errorresolution(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["http", "lightfuzz", "excavate"]
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
                    "POSSIBLE Unsafe Deserialization. Parameter: [TextBox1] Parameter Type: [POSTPARAM]"
                    in e.data["description"]
                    and "Technique: [Error Resolution (Baseline: [500]  -> Probe: [200] )] Serialization Payload: [dotnet_base64]"
                    in e.data["description"]
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
            print("@@@@")
            print(e.type)
            print(e.data)
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
                    "POSSIBLE Unsafe Deserialization. Parameter: [TextBox1] Parameter Type: [POSTPARAM] Original Value: [AAEAAAD/////AQAAAAAAAAAGAQAAAAdndXN0YXZvCw==]"
                    in e.data["description"]
                    and "Technique: [Error Resolution (Baseline: [500]  -> Probe: [200] )] Serialization Payload: [dotnet_base64]"
                    in e.data["description"]
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


# Serialization Module (Error Resolution - Transient Baseline)
# Simulates a server that returns 500 on the first request (baseline), then 200 for everything after.
# The confirmation re-send of the control payload should catch this and suppress the finding.
class Test_Lightfuzz_serial_errorresolution_transient_baseline(Test_Lightfuzz_serial_errorresolution):
    request_count = 0

    def request_handler(self, request):
        post_params = request.form

        if "TextBox1" not in post_params.keys():
            return Response(self.dotnet_serial_html, status=200)

        self.request_count += 1
        # First request (baseline) returns 500, all subsequent requests return 200
        if self.request_count <= 1:
            return Response(self.dotnet_serial_error, status=500)
        else:
            return Response("<html><body>OK</body></html>", status=200)

    def check(self, module_test, events):
        no_finding_emitted = True
        for e in events:
            if e.type == "FINDING" and "Error Resolution" in e.data.get("description", ""):
                no_finding_emitted = False
        assert no_finding_emitted, "False positive Error Resolution finding was emitted despite transient baseline"


# Serialization Module (Error Resolution - Multi-Language Family False Positive)
# Simulates a server where ALL serialization payloads resolve the error (500->200),
# spanning multiple language families. The multi-family check should discard them all.
class Test_Lightfuzz_serial_errorresolution_multi_language(Test_Lightfuzz_serial_errorresolution):
    def request_handler(self, request):
        post_params = request.form

        if "TextBox1" not in post_params.keys():
            return Response(self.dotnet_serial_html, status=200)

        # __VIEWSTATE mismatch triggers the baseline path
        if post_params["__VIEWSTATE"] != "/wEPDwULLTE5MTI4MzkxNjVkZNt7ICM+GixNryV6ucx+srzhXlwP":
            return Response(self.dotnet_serial_error, status=500)

        # ALL payloads "resolve" the error - this is the false positive scenario
        return Response("<html><body>OK</body></html>", status=200)

    def check(self, module_test, events):
        no_finding_emitted = True
        for e in events:
            if e.type == "FINDING" and "Error Resolution" in e.data.get("description", ""):
                no_finding_emitted = False
        assert no_finding_emitted, (
            "False positive Error Resolution finding was emitted despite multiple language families triggering"
        )


class Test_Lightfuzz_serial_errorresolution_nonstandard_status(Test_Lightfuzz_serial_errorresolution):
    """A baseline with a non-standard status code (>511, e.g. GlobalProtect's 512)
    should not produce an Error Resolution finding even if the probe returns 200."""

    def request_handler(self, request):
        dotnet_serial_error_resolved = (
            "<html><body>Deserialization successful! Object type: System.String</body></html>"
        )
        post_params = request.form

        if "TextBox1" not in post_params.keys():
            return Response(self.dotnet_serial_html, status=200)

        else:
            if post_params["__VIEWSTATE"] != "/wEPDwULLTE5MTI4MzkxNjVkZNt7ICM+GixNryV6ucx+srzhXlwP":
                # Non-standard status code (like GlobalProtect's 512)
                return Response(self.dotnet_serial_error, status=512)
            if post_params["TextBox1"] == "AAEAAAD/////AQAAAAAAAAAGAQAAAAdndXN0YXZvCw==":
                return Response(dotnet_serial_error_resolved, status=200)
            else:
                return Response(self.dotnet_serial_error, status=512)

    def check(self, module_test, events):
        no_finding_emitted = True
        for e in events:
            if e.type == "FINDING" and "Error Resolution" in e.data.get("description", ""):
                no_finding_emitted = False
        assert no_finding_emitted, (
            "False positive Error Resolution finding was emitted for non-standard baseline status code (>511)"
        )


# Python pickle Error Resolution — verifies the new python_pickle_base64
# payload flips a baseline UnpicklingError 500 into a 200, which is the
# canonical detection path for all languages in the serial submodule.
class Test_Lightfuzz_serial_python_pickle(Test_Lightfuzz_serial_errorresolution):
    modules_overrides = ["http", "lightfuzz", "excavate", "paramminer_getparams"]
    config_overrides = {
        "interactsh_disable": True,
        "modules": {
            "lightfuzz": {"enabled_submodules": ["serial"]},
            # Make paramminer discover the pklparam on /deser_pickle.
            "paramminer_getparams": {"wordlist": "", "recycle_words": False, "skip_boring_words": True},
        },
    }

    PICKLE_BENIGN_B64 = "gASVCAAAAAAAAACMBHRlc3SULg=="

    # Seed value is `aTowOw==` — base64 of `i:0;` (PHP-serialized integer).
    # bbot's envelope system detects the outer B64 envelope and would
    # normally re-pack any outgoing probe as base64 again — which would
    # double-encode serial's already-base64 payloads and break detection.
    # Because serial sets `skip_envelopes = True`, the bypass kicks in and
    # the raw outer value is forwarded to `is_possibly_serialized` (which
    # accepts base64-looking strings) and probes are sent verbatim.
    SEED_HREF = '<html><a href="/deser_pickle?pklparam=aTowOw==">pkl</a></html>'

    async def setup_after_prep(self, module_test):
        # Seed the parameter directly so the scan doesn't depend on
        # paramminer discovering it.
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": self.SEED_HREF, "status": 200}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)
        expect_args = re.compile("/deser_pickle")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

    def request_handler(self, request):
        value = request.args.get("pklparam", "")
        if value == self.PICKLE_BENIGN_B64:
            return Response("<html>ok</html>", status=200)
        return Response("<html>UnpicklingError: invalid pickle</html>", status=500)

    def check(self, module_test, events):
        pickle_finding = False
        for e in events:
            if e.type == "FINDING":
                desc = e.data["description"]
                if (
                    "POSSIBLE Unsafe Deserialization" in desc
                    and "Serialization Payload: [python_pickle_base64]" in desc
                ):
                    pickle_finding = True
        assert pickle_finding, "Python pickle Error Resolution FINDING not emitted"


# Python pickle OOB (blind RCE) — verifies that the new pickle OOB payload
# triggers an interactsh interaction when deserialized, giving a CONFIRMED
# blind-RCE finding without needing response-body inspection.
class Test_Lightfuzz_serial_pickle_interactsh(Test_Lightfuzz_serial_python_pickle):
    config_overrides = {
        "interactsh_disable": False,
        "modules": {
            "lightfuzz": {"enabled_submodules": ["serial"]},
        },
    }

    async def setup_before_prep(self, module_test):
        self.interactsh_mock_instance = module_test.mock_interactsh("lightfuzz")

        def mock_interactsh_factory(*args, **kwargs):
            return self.interactsh_mock_instance

        from bbot.core.helpers.helper import ConfigAwareHelper

        module_test.monkeypatch.setattr(ConfigAwareHelper, "interactsh", mock_interactsh_factory)

    def request_handler(self, request):
        import base64 as _b64
        import re as _re

        value = request.args.get("pklparam", "")
        try:
            decoded = _b64.b64decode(value)
        except Exception:
            decoded = b""
        # Look for the interactsh subdomain tag embedded in the pickle bytes.
        # The subdomain is UTF-8 in the pickle stream, so scan the raw bytes.
        match = _re.search(rb"([a-z]+)\.fakedomain\.fakeinteractsh\.com", decoded)
        if match:
            tag = match.group(1).decode("ascii")
            self.interactsh_mock_instance.mock_interaction(tag)
        return Response("<html>ok</html>", status=200)

    def check(self, module_test, events):
        oob_finding = False
        for e in events:
            if e.type == "FINDING":
                desc = e.data["description"]
                if "Python pickle OOB RCE (OOB Interaction)" in desc and "Payload: [python_pickle_oob]" in desc:
                    oob_finding = True
        assert oob_finding, "Python pickle OOB interactsh FINDING not emitted"


# Java URLDNS OOB — verifies that the pure-Python URLDNS payload built
# from scratch triggers an interactsh DNS lookup callback when a mock
# "Java" endpoint "deserializes" it. Because the URLDNS gadget requires
# only java.util.HashMap + java.net.URL (both stdlib), it fires against
# any Java deserialization sink without depending on app-specific gadget
# classes.
class Test_Lightfuzz_serial_urldns_interactsh(Test_Lightfuzz_serial_pickle_interactsh):
    def request_handler(self, request):
        import base64 as _b64
        import re as _re

        value = request.args.get("pklparam", "")
        try:
            decoded = _b64.b64decode(value)
        except Exception:
            decoded = b""
        # The URLDNS payload embeds the host string as a Java-modified-UTF
        # with a 2-byte length prefix. The host bytes appear verbatim, so
        # we can grep for the interactsh subdomain directly.
        match = _re.search(rb"([a-z]+)\.fakedomain\.fakeinteractsh\.com", decoded)
        if match:
            tag = match.group(1).decode("ascii")
            self.interactsh_mock_instance.mock_interaction(tag)
        return Response("<html>ok</html>", status=200)

    def check(self, module_test, events):
        urldns_finding = False
        for e in events:
            if e.type == "FINDING":
                desc = e.data["description"]
                if "Java URLDNS OOB (OOB Interaction)" in desc and "Payload: [java_urldns_oob]" in desc:
                    urldns_finding = True
        assert urldns_finding, "Java URLDNS OOB interactsh FINDING not emitted"


# CMDi echo canary
class Test_Lightfuzz_cmdi(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["http", "lightfuzz", "excavate"]
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
            decoded = unquote(value)
            # Simulate a Linux bash-family shell: evaluate $((A*B)) first so
            # the arithmetic confirmation probe lands a product value, then
            # fall back to plain-echo reflection for the generic probe.
            arith = re.search(r"&& echo \$\(\((\d+)\*(\d+)\)\) &&", decoded)
            if arith:
                cmdi_value = str(int(arith.group(1)) * int(arith.group(2)))
            elif "&& echo " in decoded:
                cmdi_value = decoded.split("&& echo ")[1].split(" ")[0]
            else:
                cmdi_value = decoded
            cmdi_block = f"""
        <section class=blog-header>
            <h1>0 search results for '{cmdi_value}'</h1>
            <hr>
        </section>
        """
            return Response(cmdi_block, status=200)

        return Response(parameter_block, status=200)

    async def setup_after_prep(self, module_test):
        # Respect the numeric_only=True contract so int() conversions in the
        # arithmetic canary path succeed. Non-numeric calls still receive the
        # original deterministic letter string.
        def rand_string(*args, **kwargs):
            if kwargs.get("numeric_only"):
                return "1234567890"
            return "AAAAAAAAAAAAAA"

        module_test.scan.modules["lightfuzz"].helpers.rand_string = rand_string
        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

    def check(self, module_test, events):
        web_parameter_emitted = False
        cmdi_posix_arith_finding = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [search]" in e.data["description"]:
                    web_parameter_emitted = True

            if e.type == "FINDING":
                if (
                    "POSSIBLE OS Command Injection. Parameter: [search] Parameter Type: [GETPARAM] Detection Method: [arithmetic canary (POSIX)] CMD Probe Delimeters: [&&]"
                    in e.data["description"]
                ):
                    cmdi_posix_arith_finding = True

        assert web_parameter_emitted, "WEB_PARAMETER was not emitted"
        assert cmdi_posix_arith_finding, "POSIX arithmetic canary CMDi FINDING not emitted"


# CMDi Windows `set /A` canary: simulates a cmd.exe target that evaluates
# `set /A A*B` and prints the product. The arithmetic confirmation cascade
# should land on the Windows arithmetic probe (after the POSIX probe returns
# the literal) and emit a HIGH-confidence finding labeled as cmd.
class Test_Lightfuzz_cmdi_windows(Test_Lightfuzz_cmdi):
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
            decoded = unquote(value)
            # Simulate cmd.exe: evaluate `set /A A*B` and print the product;
            # reflect $((A*B)) literal (cmd doesn't expand POSIX arithmetic);
            # reflect `echo X` args verbatim.
            setA = re.search(r"&& set /A (\d+)\*(\d+) &&", decoded)
            if setA:
                result = int(setA.group(1)) * int(setA.group(2))
                return Response(f"<section><h1>{result}</h1></section>", status=200)
            if "&& echo " in decoded:
                cmdi_value = decoded.split("&& echo ")[1].split(" ")[0]
                return Response(
                    f"<section><h1>0 search results for '{cmdi_value}'</h1></section>",
                    status=200,
                )
            return Response(f"<section><h1>0 search results for '{decoded}'</h1></section>", status=200)
        return Response(parameter_block, status=200)

    def check(self, module_test, events):
        web_parameter_emitted = False
        windows_arith_finding = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [search]" in e.data["description"]:
                    web_parameter_emitted = True
            if e.type == "FINDING":
                desc = e.data["description"]
                if (
                    "Detection Method: [arithmetic canary (cmd)]" in desc
                    and "Parameter: [search]" in desc
                    and "[&&]" in desc
                ):
                    windows_arith_finding = True
        assert web_parameter_emitted, "WEB_PARAMETER was not emitted"
        assert windows_arith_finding, "Windows cmd arithmetic canary HIGH-confidence FINDING was not emitted"


# CMDi parser-error reflection: simulates a parser (SQL, JSON, YAML) that
# reflects the probe's offending token back in its error. Under the three-
# stage cascade this should NOT produce a "Possible Command Injection"
# finding at all, because neither the POSIX `$((A*B))` nor the Windows
# `set /A A*B` confirmation probe can coax a shell product out of a text
# parser. Instead, a separate "Possible Parameter Reflection" finding is
# emitted to preserve the adjacent-vuln signal without overclaiming cmdi.
class Test_Lightfuzz_cmdi_parser_reflection_downgrade(Test_Lightfuzz_cmdi):
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
            decoded = unquote(value)
            # Real parsers only trip when a shell-style metachar breaks the
            # surrounding syntax. Require a delimiter before the token so the
            # AAAA false-positive probe does not accidentally reflect.
            arith_match = re.search(r"[;|&]\s*echo\s+(\$\(\(\d+\*\d+\)\))", decoded)
            if arith_match:
                return Response(
                    f'{{"error":"parse error near {arith_match.group(1)}"}}',
                    status=500,
                    mimetype="application/json",
                )
            setA_match = re.search(r"[;|&]\s*set\s*/A\s+(\d+\*\d+)", decoded)
            if setA_match:
                return Response(
                    f'{{"error":"parse error near {setA_match.group(1)}"}}',
                    status=500,
                    mimetype="application/json",
                )
            generic_match = re.search(r"[;|&]\s*echo\s+(\d+)", decoded)
            if generic_match:
                return Response(
                    f'{{"error":"parse error near {generic_match.group(1)}"}}',
                    status=500,
                    mimetype="application/json",
                )
            return Response('{"results":[]}', status=200, mimetype="application/json")
        return Response(parameter_block, status=200)

    def check(self, module_test, events):
        cmdi_finding = False
        reflection_finding = False
        for e in events:
            if e.type == "FINDING":
                name = e.data.get("name", "")
                if "Command Injection" in name:
                    cmdi_finding = True
                if "Parameter Reflection" in name:
                    reflection_finding = True

        assert not cmdi_finding, (
            "Parser-error reflection should NOT produce a Possible Command "
            "Injection finding under the three-stage cascade (neither POSIX "
            "nor Windows arithmetic probe can coax a product out of a text "
            "parser)."
        )
        assert reflection_finding, (
            "Expected a Possible Parameter Reflection finding for the "
            "reflection-only detection path (preserves adjacent-vuln signal "
            "without overclaiming cmdi)."
        )


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

        # Mock at the helper creation level BEFORE modules are set up
        def mock_interactsh_factory(*args, **kwargs):
            return self.interactsh_mock_instance

        # Apply the mock to the core helpers so modules get the mock during setup
        from bbot.core.helpers.helper import ConfigAwareHelper

        module_test.monkeypatch.setattr(ConfigAwareHelper, "interactsh", mock_interactsh_factory)

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

            if e.type == "FINDING":
                if (
                    "OS Command Injection (OOB Interaction) Type: [GETPARAM] Parameter Name: [search] Probe: [&&]"
                    in e.data["description"]
                ):
                    cmdi_interacttsh_finding_emitted = True

        assert web_parameter_emitted, "WEB_PARAMETER was not emitted"
        assert cmdi_interacttsh_finding_emitted, "interactsh CMDi FINDING not emitted"


# SSRF interactsh
class Test_Lightfuzz_ssrf(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["http", "lightfuzz", "excavate"]

    @staticmethod
    def extract_subdomain_tag(data):
        # Try both URL-encoded and non-encoded forms
        for pattern in [
            r"url=https?%3A%2F%2F(.+?)\.fakedomain\.fakeinteractsh\.com",
            r"url=https?://(.+?)\.fakedomain\.fakeinteractsh\.com",
        ]:
            match = re.search(pattern, data)
            if match:
                return match.group(1)

    config_overrides = {
        "interactsh_disable": False,
        "modules": {
            "lightfuzz": {
                "enabled_submodules": ["ssrf"],
            }
        },
    }

    def request_handler(self, request):
        qs = str(request.query_string.decode())

        parameter_block = """
        <section class=search>
            <form action=/ method=GET>
                <input type=text placeholder='Enter URL...' name=url>
                <button type=submit class=button>Fetch</button>
            </form>
        </section>
        """

        if "url=" in qs:
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
        ssrf_dns_finding_emitted = False
        ssrf_http_finding_emitted = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [url]" in e.data["description"]:
                    web_parameter_emitted = True

            if e.type == "FINDING":
                if (
                    "Server-Side Request Forgery (OOB Interaction) Type: [GETPARAM] Parameter Name: [url]"
                    in e.data["description"]
                ):
                    if "Interaction Protocol: [dns]" in e.data["description"]:
                        ssrf_dns_finding_emitted = True
                        assert e.data["confidence"] == "MEDIUM", (
                            f"DNS SSRF should be MEDIUM, got {e.data['confidence']}"
                        )
                    elif "Interaction Protocol: [http]" in e.data["description"]:
                        ssrf_http_finding_emitted = True
                        assert e.data["confidence"] == "CONFIRMED", (
                            f"HTTP SSRF should be CONFIRMED, got {e.data['confidence']}"
                        )

        assert web_parameter_emitted, "WEB_PARAMETER was not emitted"
        assert ssrf_dns_finding_emitted, "interactsh SSRF DNS FINDING not emitted"
        assert ssrf_http_finding_emitted, "interactsh SSRF HTTP FINDING not emitted"


class Test_Lightfuzz_speculative(ModuleTestBase):
    targets = ["http://127.0.0.1:8888/"]
    modules_overrides = ["http", "excavate", "paramminer_getparams", "lightfuzz"]
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
        module_test.scan.modules["lightfuzz"].helpers.rand_string = lambda *args, **kwargs: (
            "1234567890" if kwargs.get("numeric_only") else "AAAAAAAAAAAAAA"
        )
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
    modules_overrides = ["http", "excavate", "lightfuzz"]
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
            <h1>Padding is invalid</h1>
            <hr>
        </section>
        """
        if "secret=" in qs:
            value = qs.split("=")[1]
            if value:
                return Response(crypto_block, status=200)

        return Response(parameter_block, status=200)

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["lightfuzz"].helpers.rand_string = lambda *args, **kwargs: (
            "1234567890" if kwargs.get("numeric_only") else "AAAAAAAAAAAAAA"
        )
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
    modules_overrides = ["http", "excavate", "lightfuzz"]
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
        module_test.scan.modules["lightfuzz"].helpers.rand_string = lambda *args, **kwargs: (
            "1234567890" if kwargs.get("numeric_only") else "AAAAAAAAAAAAAA"
        )
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
    modules_overrides = ["http", "excavate", "lightfuzz"]
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
                if (
                    e.data["description"]
                    == "Padding Oracle Vulnerability. Block size: [16] Parameter: [encrypted_data] Parameter Type: [POSTPARAM] Original Value: [dplyorsu8VUriMW/8DqVDU6kRwL/FDk3Q%2B4GXVGZbo0CTh9YX1YvzZZJrYe4cHxvAICyliYtp1im4fWoOa54Zg%3D%3D] Envelopes: [URL-Encoded]"
                ):
                    padding_oracle_detected = True

        assert web_parameter_extracted, "Web parameter was not extracted"
        assert cryptographic_parameter_finding, "Cryptographic parameter not detected"
        assert padding_oracle_detected, "Padding oracle vulnerability was not detected"


class Test_Lightfuzz_PaddingOracleDetection_Reflecting(Test_Lightfuzz_PaddingOracleDetection):
    """Padding oracle test where the server reflects the submitted value in the response body.
    Without reflection-stripping logic, every probe body differs and detection always fails."""

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
                    response_content = f"Padding error detected. Input: {encrypted_data}"
                elif "4GXVGZbo0DTh9YX1YvzZZJrYe4cHxvAICyliYtp1im4fWoOa54Zg" in encrypted_data:
                    response_content = f"DIFFERENT CRYPTOGRAPHIC ERROR. Input: {encrypted_data}"
                elif "AAAAAAA" in encrypted_data:
                    response_content = f"YET DIFFERENT CRYPTOGRAPHIC ERROR. Input: {encrypted_data}"
                else:
                    response_content = f"Decryption failed. Input: {encrypted_data}"

            return Response(response_content, status=200)
        else:
            return Response(default_html_response, status=200)

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
                    "Probable Cryptographic Parameter." in e.data["description"]
                    and "encrypted_data" in e.data["description"]
                ):
                    cryptographic_parameter_finding = True

            if e.type == "FINDING":
                if (
                    "Padding Oracle Vulnerability. Block size: [16]" in e.data["description"]
                    and "encrypted_data" in e.data["description"]
                ):
                    padding_oracle_detected = True

        assert web_parameter_extracted, "Web parameter was not extracted"
        assert cryptographic_parameter_finding, "Cryptographic parameter not detected"
        assert padding_oracle_detected, "Padding oracle vulnerability was not detected"


class Test_Lightfuzz_PaddingOracleDetection_Noisy(Test_Lightfuzz_PaddingOracleDetection):
    """Padding oracle negative test: the server returns different responses for ~30 byte values,
    which exceeds any valid block size. This should NOT produce a FINDING."""

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
                # Check for the data block from the original ciphertext (mutate/truncate probes)
                if "4GXVGZbo0DTh9YX1YvzZZJrYe4cHxvAICyliYtp1im4fWoOa54Zg" in encrypted_data:
                    response_content = "DIFFERENT CRYPTOGRAPHIC ERROR"
                # Padding oracle probes: null IV + padding blocks produce long runs of A's in base64
                elif encrypted_data.startswith("AAAAAAAAAAAAAAAA"):
                    try:
                        decoded = base64.b64decode(encrypted_data)
                        if len(decoded) >= 32:
                            varying_byte = decoded[31]
                            # 30 byte values produce a different response - way over any block size
                            if 100 <= varying_byte <= 129:
                                response_content = "Noisy error type A"
                            else:
                                response_content = "Decryption failed"
                        else:
                            response_content = "Decryption failed"
                    except Exception:
                        response_content = "Decryption failed"
                # Arbitrary probe
                elif "AAAAAAA" in encrypted_data:
                    response_content = "YET DIFFERENT CRYPTOGRAPHIC ERROR"
                else:
                    response_content = "Decryption failed"

            return Response(response_content, status=200)
        else:
            return Response(default_html_response, status=200)

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
                    "Probable Cryptographic Parameter." in e.data["description"]
                    and "encrypted_data" in e.data["description"]
                ):
                    cryptographic_parameter_finding = True
            if e.type == "FINDING":
                if "Padding Oracle" in e.data["description"]:
                    padding_oracle_detected = True

        assert web_parameter_extracted, "Web parameter was not extracted"
        assert cryptographic_parameter_finding, "Cryptographic parameter not detected"
        assert not padding_oracle_detected, (
            "Padding oracle should NOT be detected when 30 probes differ (exceeds block size)"
        )


class Test_Lightfuzz_PaddingOracleDetection_NarrowCharset(ModuleTestBase):
    """Parameters with values that use a narrow consecutive character set (e.g. only A-P)
    round-trip as valid base64 but are not actual cryptographic data.
    The narrow charset check should reject these, preventing false findings."""

    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["http", "excavate", "lightfuzz"]
    config_overrides = {
        "interactsh_disable": True,
        "modules": {
            "lightfuzz": {
                "enabled_submodules": ["crypto"],
            }
        },
    }

    # A-P only value: valid base64 round-trip, but narrow charset (span=15)
    narrow_charset_value = "BPIDFOPFGNLIBNFGAEPBMIIKPHEFGOJKOMACMBJJLOPKFIGMKALJDBHCMAMHIKIMDOFDHIBAHEJBIIGMIDKANCMFGJAIEKLPCLFDMELEAGBILMHLAPFKNNBAMPPNDEEP"

    def request_handler(self, request):
        return Response("<html><body><p>Welcome</p></body></html>", status=200)

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests_handler(expect_args=re.compile(".*"), request_handler=self.request_handler)

        parent_event = module_test.scan.make_event(
            "http://127.0.0.1:8888/",
            "URL",
            module_test.scan.root_event,
            module="http",
            tags=["status-200", "distance-0"],
        )

        data = {
            "host": "127.0.0.1",
            "type": "COOKIE",
            "name": "custom_session_cookie",
            "original_value": self.narrow_charset_value,
            "url": "http://127.0.0.1:8888/",
            "description": "Test narrow charset cookie",
        }
        seed_event = module_test.scan.make_event(data, "WEB_PARAMETER", parent_event, tags=["distance-0"])
        await module_test.scan.ingress_module.incoming_event_queue.put(seed_event)

    def check(self, module_test, events):
        crypto_finding = False
        padding_oracle_finding = False
        for e in events:
            if e.type == "FINDING":
                if "Cryptographic Parameter" in e.data["description"]:
                    crypto_finding = True
                if "Padding Oracle" in e.data["description"]:
                    padding_oracle_finding = True

        assert not crypto_finding, "Narrow-charset parameter should NOT be identified as cryptographic"
        assert not padding_oracle_finding, "Narrow-charset parameter should NOT trigger padding oracle detection"


class Test_Lightfuzz_PaddingOracleDetection_Jitter(Test_Lightfuzz_PaddingOracleDetection):
    """Padding oracle negative test: the server produces inconsistent responses across rounds.
    The first round may trigger detection, but the confirmation round should fail,
    suppressing the jitter-based false positive."""

    oracle_request_count = 0

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

                if "4GXVGZbo0DTh9YX1YvzZZJrYe4cHxvAICyliYtp1im4fWoOa54Zg" in encrypted_data:
                    response_content = "DIFFERENT CRYPTOGRAPHIC ERROR"
                elif encrypted_data.startswith("AAAAAAAAAAAAAAAA"):
                    Test_Lightfuzz_PaddingOracleDetection_Jitter.oracle_request_count += 1
                    # First 254 requests (round 1): produce oracle-like signal (1 differ)
                    if Test_Lightfuzz_PaddingOracleDetection_Jitter.oracle_request_count <= 254:
                        try:
                            decoded = base64.b64decode(encrypted_data)
                            if len(decoded) >= 32:
                                varying_byte = decoded[31]
                                if varying_byte == 100:
                                    response_content = "Padding error detected"
                                else:
                                    response_content = "Decryption failed"
                            else:
                                response_content = "Decryption failed"
                        except Exception:
                            response_content = "Decryption failed"
                    else:
                        # Confirmation round: all responses identical (no oracle signal)
                        response_content = "Decryption failed"
                elif "AAAAAAA" in encrypted_data:
                    response_content = "YET DIFFERENT CRYPTOGRAPHIC ERROR"
                else:
                    response_content = "Decryption failed"

            return Response(response_content, status=200)
        else:
            return Response(default_html_response, status=200)

    def check(self, module_test, events):
        web_parameter_extracted = False
        padding_oracle_detected = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [encrypted_data] (POST Form" in e.data["description"]:
                    web_parameter_extracted = True
            if e.type == "FINDING":
                if "Padding Oracle" in e.data["description"]:
                    padding_oracle_detected = True

        assert web_parameter_extracted, "Web parameter was not extracted"
        assert not padding_oracle_detected, (
            "Padding oracle should NOT be detected when confirmation round fails (jitter false positive)"
        )


class Test_Lightfuzz_XSS_jsquotecontext(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["http", "lightfuzz", "excavate", "paramminer_getparams"]
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

            if input_value is not None:
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

            if input_value is not None:
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


class Test_Lightfuzz_esi(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["http", "lightfuzz", "excavate"]
    config_overrides = {
        "interactsh_disable": True,
        "modules": {
            "lightfuzz": {
                "enabled_submodules": ["esi"],
            }
        },
    }

    def request_handler(self, request):
        qs = str(request.query_string.decode())

        parameter_block = """
        <section class=search>
            <form action=/ method=GET>
                <input type=text placeholder='Search...' name=search>
                <button type=submit class=button>Search</button>
            </form>
        </section>
        """
        if "search=" in qs:
            value = qs.split("=")[1]
            if "&" in value:
                value = value.split("&")[0]
            # Decode the URL-encoded value
            decoded_value = unquote(value)
            # Simulate ESI processing: if the payload contains <!--esi-->, remove it
            if "<!--esi-->" in decoded_value:
                # ESI processor removes <!--esi--> tag, leaving the rest
                processed_value = decoded_value.replace("<!--esi-->", "")
            else:
                # For non-ESI payloads, just reflect the value as-is
                processed_value = decoded_value

            esi_block = f"""
        <section class=blog-header>
            <h1>Search results for '{processed_value}'</h1>
            <hr>
        </section>
        """
            return Response(esi_block, status=200)

        return Response(parameter_block, status=200)

    async def setup_after_prep(self, module_test):
        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

    def check(self, module_test, events):
        web_parameter_emitted = False
        esi_finding_emitted = False

        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [search]" in e.data["description"]:
                    web_parameter_emitted = True

            if e.type == "FINDING":
                if "Edge Side Include. Parameter: [search] Parameter Type: [GETPARAM]" in e.data["description"]:
                    esi_finding_emitted = True

        assert web_parameter_emitted, "WEB_PARAMETER was not emitted"
        assert esi_finding_emitted, "ESI FINDING not emitted"


# ESI remote-include OOB — verifies the new `<esi:include>` probe triggers
# an interactsh callback when the edge actually fetches the include URL,
# producing a CRITICAL CONFIRMED finding separate from the tag-strip one.
class Test_Lightfuzz_esi_interactsh(Test_Lightfuzz_esi):
    config_overrides = {
        "interactsh_disable": False,
        "modules": {
            "lightfuzz": {"enabled_submodules": ["esi"]},
        },
    }

    async def setup_before_prep(self, module_test):
        self.interactsh_mock_instance = module_test.mock_interactsh("lightfuzz")

        def mock_interactsh_factory(*args, **kwargs):
            return self.interactsh_mock_instance

        from bbot.core.helpers.helper import ConfigAwareHelper

        module_test.monkeypatch.setattr(ConfigAwareHelper, "interactsh", mock_interactsh_factory)

    def request_handler(self, request):
        import re as _re

        qs = str(request.query_string.decode())
        # Parameter block must include the search form so excavate can
        # extract the `search` GETPARAM on the initial fetch; otherwise
        # esi only fuzzes the HEADER test param and the include probe
        # never reaches us.
        parameter_block = """
        <section class=search>
            <form action=/ method=GET>
                <input type=text placeholder='Search...' name=search>
                <button type=submit class=button>Search</button>
            </form>
        </section>
        """
        if "search=" in qs:
            # Split only at the FIRST `=` — the include payload's `src=`
            # embeds unencoded `=` characters that would otherwise
            # truncate the value.
            value = qs.split("=", 1)[1]
            if "&" in value:
                value = value.split("&")[0]
            decoded = unquote(value)
            # Simulate an edge that fetches esi:include src URLs. Extract
            # the interactsh subdomain from within an include payload and
            # fire a mock interaction to prove the OOB detection path.
            if "<esi:include" in decoded:
                include_match = _re.search(r"([a-z]+)\.fakedomain\.fakeinteractsh\.com", decoded)
                if include_match:
                    tag = include_match.group(1)
                    self.interactsh_mock_instance.mock_interaction(tag)
            return Response(f"<html>search: '{decoded}'</html>", status=200)
        return Response(parameter_block, status=200)

    def check(self, module_test, events):
        remote_include_finding = False
        for e in events:
            if e.type == "FINDING":
                desc = e.data["description"]
                if "Edge Side Include Remote Fetch (OOB Interaction)" in desc and "Parameter: [search]" in desc:
                    remote_include_finding = True
        assert remote_include_finding, "ESI remote-include OOB FINDING not emitted"


# Envelope state isolation: crypto error detection with all submodules enabled.
# Crypto runs after sqli/cmdi/xss/path/ssti. Each prior submodule calls outgoing_probe_value()
# which must not corrupt the envelope state that crypto reads via incoming_probe_value().
class Test_Lightfuzz_envelope_isolation_crypto(Test_Lightfuzz_crypto_error):
    config_overrides = {
        "interactsh_disable": True,
        "modules": {
            "lightfuzz": {
                "enabled_submodules": ["sqli", "cmdi", "xss", "path", "ssti", "crypto", "serial", "esi"],
            }
        },
    }


# Envelope state isolation: padding oracle detection with all submodules enabled.
class Test_Lightfuzz_envelope_isolation_paddingoracle(Test_Lightfuzz_PaddingOracleDetection):
    config_overrides = {
        "interactsh_disable": True,
        "modules": {
            "lightfuzz": {
                "enabled_submodules": ["sqli", "cmdi", "xss", "path", "ssti", "crypto", "serial", "esi"],
            }
        },
    }


# Envelope state isolation: reflecting padding oracle detection with all submodules enabled.
class Test_Lightfuzz_envelope_isolation_paddingoracle_reflecting(Test_Lightfuzz_PaddingOracleDetection_Reflecting):
    config_overrides = {
        "interactsh_disable": True,
        "modules": {
            "lightfuzz": {
                "enabled_submodules": ["sqli", "cmdi", "xss", "path", "ssti", "crypto", "serial", "esi"],
            }
        },
    }


# ECB Mode Detection: ciphertext with repeated 16-byte blocks (A+B+A+B pattern)
class Test_Lightfuzz_ECBDetection(ModuleTestBase):
    targets = ["http://127.0.0.1:8888/"]
    modules_overrides = ["http", "excavate", "lightfuzz"]
    config_overrides = {
        "interactsh_disable": True,
        "modules": {
            "lightfuzz": {"enabled_submodules": ["crypto"]},
        },
    }

    # Two 16-byte blocks with non-overlapping byte values (high entropy), repeated A+B+A+B
    _block_a = bytes(range(16)).hex()  # 000102...0f
    _block_b = bytes(range(128, 144)).hex()  # 808182...8f
    ecb_ciphertext_hex = _block_a + _block_b + _block_a + _block_b

    def request_handler(self, request):
        qs = str(request.query_string.decode())
        parameter_block = f"""
        <section>
            <form action=/ method=GET>
                <input type=text value='{self.ecb_ciphertext_hex}' name=token>
                <button type=submit>Submit</button>
            </form>
        </section>
        """
        if "token=" in qs:
            return Response("OK", status=200)
        return Response(parameter_block, status=200)

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["lightfuzz"].helpers.rand_string = lambda *args, **kwargs: (
            "1234567890" if kwargs.get("numeric_only") else "AAAAAAAAAAAAAA"
        )
        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

    def check(self, module_test, events):
        ecb_detected = False
        for e in events:
            if e.type == "FINDING":
                if "ECB Mode Encryption Detected" in e.data["description"]:
                    ecb_detected = True
        assert ecb_detected, "ECB Mode Encryption FINDING not emitted"


# ECB Negative: all unique blocks, should NOT detect ECB
class Test_Lightfuzz_ECBDetection_Negative(ModuleTestBase):
    targets = ["http://127.0.0.1:8888/"]
    modules_overrides = ["http", "excavate", "lightfuzz"]
    config_overrides = {
        "interactsh_disable": True,
        "modules": {
            "lightfuzz": {"enabled_submodules": ["crypto"]},
        },
    }

    # 4 unique 16-byte blocks with non-overlapping byte values (high entropy, no repeats)
    unique_ciphertext_hex = (
        bytes(range(0, 16)).hex()
        + bytes(range(64, 80)).hex()
        + bytes(range(128, 144)).hex()
        + bytes(range(192, 208)).hex()
    )

    def request_handler(self, request):
        qs = str(request.query_string.decode())
        parameter_block = f"""
        <section>
            <form action=/ method=GET>
                <input type=text value='{self.unique_ciphertext_hex}' name=token>
                <button type=submit>Submit</button>
            </form>
        </section>
        """
        if "token=" in qs:
            return Response("OK", status=200)
        return Response(parameter_block, status=200)

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["lightfuzz"].helpers.rand_string = lambda *args, **kwargs: (
            "1234567890" if kwargs.get("numeric_only") else "AAAAAAAAAAAAAA"
        )
        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

    def check(self, module_test, events):
        for e in events:
            if e.type == "FINDING":
                assert "ECB Mode Encryption Detected" not in e.data["description"], (
                    "ECB falsely detected on unique blocks"
                )


# CBC Bit-Flipping Detection: server returns different responses for different byte-position mutations
class Test_Lightfuzz_CBCBitflipDetection(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["http", "excavate", "lightfuzz"]
    config_overrides = {
        "interactsh_disable": True,
        "modules": {
            "lightfuzz": {"enabled_submodules": ["crypto"]},
        },
    }

    # 3 blocks of 16 bytes = 48 bytes, base64-encoded
    original_b64 = base64.b64encode(bytes(range(48))).decode()

    def request_handler(self, request):
        encrypted_value = quote(self.original_b64)
        default_html = f"""
        <html><body>
            <form action="/process" method="post">
                <input type="hidden" name="cipher" value="{encrypted_value}" />
                <button type="submit">Process</button>
            </form>
        </body></html>
        """
        if "/process" in request.url and request.method == "POST":
            if request.form and request.form.get("cipher"):
                cipher_val = request.form["cipher"]
                try:
                    raw = base64.b64decode(cipher_val)
                except Exception:
                    return Response("Invalid input", status=200)
                # Penultimate block starts at byte 16
                # Check which byte in the penultimate block differs from original
                original_raw = bytes(range(48))
                if len(raw) == len(original_raw):
                    penultimate_start = 16
                    for i in range(penultimate_start, penultimate_start + 16):
                        if raw[i] != original_raw[i]:
                            # First byte (pos 16) vs middle byte (pos 24) produce different responses
                            if i < penultimate_start + 8:
                                return Response("Decryption result: type A", status=200)
                            else:
                                return Response("Decryption result: type B", status=200)
                return Response("Decryption failed", status=200)
            return Response("Decryption failed", status=200)
        return Response(default_html, status=200)

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests_handler(expect_args=re.compile(".*"), request_handler=self.request_handler)

    def check(self, module_test, events):
        cbc_bitflip_detected = False
        for e in events:
            if e.type == "FINDING":
                if "CBC Bit-Flipping Detected" in e.data["description"]:
                    cbc_bitflip_detected = True
        assert cbc_bitflip_detected, "CBC Bit-Flipping Detected FINDING not emitted"


# CBC Bit-Flipping Negative: server returns identical response regardless of mutation position
class Test_Lightfuzz_CBCBitflipDetection_Negative(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["http", "excavate", "lightfuzz"]
    config_overrides = {
        "interactsh_disable": True,
        "modules": {
            "lightfuzz": {"enabled_submodules": ["crypto"]},
        },
    }

    original_b64 = base64.b64encode(bytes(range(48))).decode()

    def request_handler(self, request):
        encrypted_value = quote(self.original_b64)
        default_html = f"""
        <html><body>
            <form action="/process" method="post">
                <input type="hidden" name="cipher" value="{encrypted_value}" />
                <button type="submit">Process</button>
            </form>
        </body></html>
        """
        if "/process" in request.url and request.method == "POST":
            return Response("Decryption failed", status=200)
        return Response(default_html, status=200)

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests_handler(expect_args=re.compile(".*"), request_handler=self.request_handler)

    def check(self, module_test, events):
        for e in events:
            if e.type == "FINDING":
                assert "CBC Bit-Flipping Detected" not in e.data["description"], (
                    "CBC Bit-Flipping falsely detected on identical responses"
                )


# CBC Bit-Flipping without Padding Oracle: server never fails decryption (OPENSSL_ZERO_PADDING equivalent).
# Every input produces a unique response derived from the submitted value — no padding validity leaked.
# Padding oracle sends ~254 probes that all get unique responses → differ_count >> block_size → not detected.
# CBC bit-flip probes still produce different responses → detected.
class Test_Lightfuzz_CBCBitflipDetection_NoPaddingOracle(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["http", "excavate", "lightfuzz"]
    config_overrides = {
        "interactsh_disable": True,
        "modules": {
            "lightfuzz": {"enabled_submodules": ["crypto"]},
        },
    }

    # 3 blocks of 16 bytes = 48 bytes, base64-encoded
    original_b64 = base64.b64encode(bytes(range(48))).decode()

    def request_handler(self, request):
        encrypted_value = quote(self.original_b64)
        default_html = f"""
        <html><body>
            <form action="/process" method="post">
                <input type="hidden" name="cipher" value="{encrypted_value}" />
                <button type="submit">Process</button>
            </form>
        </body></html>
        """
        if "/process" in request.url and request.method == "POST":
            if request.form and request.form.get("cipher"):
                cipher_val = request.form["cipher"]
                # No error paths — always return content derived from input.
                # Simulates OPENSSL_ZERO_PADDING: decryption never fails.
                import hashlib

                digest = hashlib.md5(cipher_val.encode()).hexdigest()
                return Response(f"Session loaded: {digest}", status=200)
            return Response("Session loaded: default", status=200)
        return Response(default_html, status=200)

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests_handler(expect_args=re.compile(".*"), request_handler=self.request_handler)

    def check(self, module_test, events):
        cbc_bitflip_detected = False
        padding_oracle_detected = False
        for e in events:
            if e.type == "FINDING":
                if "CBC Bit-Flipping Detected" in e.data["description"]:
                    cbc_bitflip_detected = True
                if "Padding Oracle Vulnerability" in e.data["description"]:
                    padding_oracle_detected = True
        assert cbc_bitflip_detected, "CBC Bit-Flipping should be detected even without padding oracle"
        assert not padding_oracle_detected, "Padding Oracle should NOT be detected when decryption never fails"


# Envelope state isolation: ECB detection with all submodules enabled
class Test_Lightfuzz_envelope_isolation_ecb(Test_Lightfuzz_ECBDetection):
    config_overrides = {
        "interactsh_disable": True,
        "modules": {
            "lightfuzz": {
                "enabled_submodules": ["sqli", "cmdi", "xss", "path", "ssti", "crypto", "serial", "esi"],
            }
        },
    }


# Envelope state isolation: CBC bit-flip detection with all submodules enabled
class Test_Lightfuzz_envelope_isolation_cbc_bitflip(Test_Lightfuzz_CBCBitflipDetection):
    config_overrides = {
        "interactsh_disable": True,
        "modules": {
            "lightfuzz": {
                "enabled_submodules": ["sqli", "cmdi", "xss", "path", "ssti", "crypto", "serial", "esi"],
            }
        },
    }


# Envelope state isolation: CBC bit-flip without padding oracle, all submodules enabled
class Test_Lightfuzz_envelope_isolation_cbc_bitflip_no_po(Test_Lightfuzz_CBCBitflipDetection_NoPaddingOracle):
    config_overrides = {
        "interactsh_disable": True,
        "modules": {
            "lightfuzz": {
                "enabled_submodules": ["sqli", "cmdi", "xss", "path", "ssti", "crypto", "serial", "esi"],
            }
        },
    }


# Test filter_event method with WAF tags
class Test_Lightfuzz_filter_event(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["http", "lightfuzz"]
    config_overrides = {
        "interactsh_disable": True,
        "modules": {
            "lightfuzz": {
                "enabled_submodules": ["xss"],
                "avoid_wafs": True,
            }
        },
    }

    async def setup_after_prep(self, module_test):
        # Create test events with WAF tags
        self.url_event_with_waf = module_test.scan.make_event(
            "http://127.0.0.1:8888/",
            "URL",
            module_test.scan.root_event,
            module="http",
            tags=["status-200", "distance-0", "waf"],
        )

        self.web_param_event_with_waf = module_test.scan.make_event(
            {
                "host": "127.0.0.1",
                "type": "GETPARAM",
                "name": "test",
                "original_value": "value",
                "url": "http://127.0.0.1:8888/",
                "description": "Test parameter",
            },
            "WEB_PARAMETER",
            module_test.scan.root_event,
            module="excavate",
            tags=["distance-0", "waf"],
        )

        self.url_event_without_waf = module_test.scan.make_event(
            "http://127.0.0.1:8888/",
            "URL",
            module_test.scan.root_event,
            module="http",
            tags=["status-200", "distance-0"],
        )

        self.web_param_event_without_waf = module_test.scan.make_event(
            {
                "host": "127.0.0.1",
                "type": "GETPARAM",
                "name": "test",
                "original_value": "value",
                "url": "http://127.0.0.1:8888/",
                "description": "Test parameter",
            },
            "WEB_PARAMETER",
            module_test.scan.root_event,
            module="excavate",
            tags=["distance-0"],
        )

    async def test_filter_event(self, module_test):
        lightfuzz_module = module_test.scan.modules["lightfuzz"]

        # Test URL event with WAF tag - should be filtered out
        result = await lightfuzz_module.filter_event(self.url_event_with_waf)
        assert result is False, "URL event with waf tag should be filtered out"

        # Test WEB_PARAMETER event with WAF tag - should be filtered out
        result = await lightfuzz_module.filter_event(self.web_param_event_with_waf)
        assert result is False, "WEB_PARAMETER event with waf tag should be filtered out"

        # Test URL event without WAF tag - should not be filtered
        result = await lightfuzz_module.filter_event(self.url_event_without_waf)
        assert result is True, "URL event without WAF tag should not be filtered"

        # Test WEB_PARAMETER event without WAF tag - should not be filtered
        result = await lightfuzz_module.filter_event(self.web_param_event_without_waf)
        assert result is True, "WEB_PARAMETER event without WAF tag should not be filtered"

    def check(self, module_test, events):
        # This test doesn't need to check events since it's testing the filter method directly
        pass


# try_post_as_get: fuzz POST parameters as GET parameters
class Test_Lightfuzz_try_post_as_get(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["http", "lightfuzz", "excavate"]
    config_overrides = {
        "interactsh_disable": True,
        "modules": {
            "lightfuzz": {
                "enabled_submodules": ["sqli"],
                "disable_post": True,
                "try_post_as_get": True,
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
        module_test.scan.modules["lightfuzz"].helpers.rand_string = lambda *args, **kwargs: (
            "1234567890" if kwargs.get("numeric_only") else "AAAAAAAAAAAAAA"
        )
        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

    def check(self, module_test, events):
        web_parameter_emitted = False
        sqli_getparam_finding_emitted = False
        sqli_postparam_finding_emitted = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [search]" in e.data["description"]:
                    web_parameter_emitted = True

            if e.type == "FINDING":
                if (
                    "Possible SQL Injection. Parameter: [search] Parameter Type: [GETPARAM] (converted from POSTPARAM) Detection Method: [Single Quote/Two Single Quote, Code Change (200->500->200)]"
                    in e.data["description"]
                ):
                    sqli_getparam_finding_emitted = True
                if "Possible SQL Injection. Parameter: [search] Parameter Type: [POSTPARAM]" in e.data["description"]:
                    sqli_postparam_finding_emitted = True

        assert web_parameter_emitted, "WEB_PARAMETER was not emitted"
        assert sqli_getparam_finding_emitted, (
            "SQLi GETPARAM (converted from POSTPARAM) FINDING not emitted (try_post_as_get failed)"
        )
        assert not sqli_postparam_finding_emitted, "POSTPARAM FINDING emitted despite disable_post=True"


# try_get_as_post: fuzz GET parameters as POST parameters
class Test_Lightfuzz_try_get_as_post(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["http", "lightfuzz", "excavate"]
    config_overrides = {
        "interactsh_disable": True,
        "modules": {
            "lightfuzz": {
                "enabled_submodules": ["sqli"],
                "try_get_as_post": True,
            }
        },
    }

    def request_handler(self, request):
        parameter_block = """
        <section class=search>
            <form action=/ method=GET>
                <input type=text placeholder='Search the blog...' name=search>
                <button type=submit class=button>Search</button>
            </form>
        </section>
        """

        if request.method == "POST" and "search" in request.form.keys():
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
        module_test.scan.modules["lightfuzz"].helpers.rand_string = lambda *args, **kwargs: (
            "1234567890" if kwargs.get("numeric_only") else "AAAAAAAAAAAAAA"
        )
        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

    def check(self, module_test, events):
        web_parameter_emitted = False
        sqli_postparam_converted_finding_emitted = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [search]" in e.data["description"]:
                    web_parameter_emitted = True

            if e.type == "FINDING":
                if (
                    "Possible SQL Injection. Parameter: [search] Parameter Type: [POSTPARAM] (converted from GETPARAM) Detection Method: [Single Quote/Two Single Quote, Code Change (200->500->200)]"
                    in e.data["description"]
                ):
                    sqli_postparam_converted_finding_emitted = True

        assert web_parameter_emitted, "WEB_PARAMETER was not emitted"
        assert sqli_postparam_converted_finding_emitted, (
            "SQLi POSTPARAM (converted from GETPARAM) FINDING not emitted (try_get_as_post failed)"
        )


# Padding Oracle Jitter Stability Pre-Check
class Test_Lightfuzz_PaddingOracleDetection_JitterStability(Test_Lightfuzz_PaddingOracleDetection):
    """Padding oracle negative test: the endpoint produces different response bodies for identical inputs
    (e.g. ADFS with embedded timestamps/nonces). The stability pre-check should detect this and skip."""

    jitter_counter = 0

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
            # Every response is unique, simulating ADFS-style dynamic content
            Test_Lightfuzz_PaddingOracleDetection_JitterStability.jitter_counter += 1
            response_content = f"Error correlation_id={Test_Lightfuzz_PaddingOracleDetection_JitterStability.jitter_counter} nonce=abc{Test_Lightfuzz_PaddingOracleDetection_JitterStability.jitter_counter}"
            return Response(response_content, status=200)
        else:
            return Response(default_html_response, status=200)

    def check(self, module_test, events):
        web_parameter_extracted = False
        padding_oracle_detected = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [encrypted_data] (POST Form" in e.data["description"]:
                    web_parameter_extracted = True
            if e.type == "FINDING":
                if "Padding Oracle" in e.data["description"]:
                    padding_oracle_detected = True

        assert web_parameter_extracted, "Web parameter was not extracted"
        assert not padding_oracle_detected, (
            "Padding oracle should NOT be detected when endpoint has jittery responses (stability pre-check should abort)"
        )


# XSS Multi-Context Reflection False Positive
class Test_Lightfuzz_xss_multicontext(Test_Lightfuzz_xss):
    """XSS negative test: parameter reflected in multiple contexts with different encoding.
    Quote survives in text content but is encoded in tag attribute. Should NOT report Tag Attribute XSS."""

    def request_handler(self, request):
        qs = str(request.query_string.decode())

        parameter_block = """
        <html>
            <form action="/" method="GET">
                <input type="text" name="path" value="default">
                <button type="submit">Submit</button>
            </form>
        </html>
        """
        if "path=" in qs:
            value = qs.split("path=")[1]
            if "&" in value:
                value = value.split("&")[0]
            decoded = unquote(value)
            # Tag attribute context: quotes are URL-encoded (safe)
            attr_value = decoded.replace('"', "%22")
            # Text content: raw reflection (quotes survive but harmless here)
            text_value = decoded
            # JS context: everything URL-encoded (safe)
            js_value = value

            html = f"""
<html>
<form action="/page?path={attr_value}" method="GET">
    <input type="text" name="path">
</form>
<h1>{text_value}</h1>
<script>if('{js_value}') {{ }}</script>
</html>
            """
            return Response(html, status=200)
        return Response(parameter_block, status=200)

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["lightfuzz"].helpers.rand_string = lambda *args, **kwargs: (
            "1234567890" if kwargs.get("numeric_only") else "AAAAAAAAAAAAAA"
        )
        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

    def check(self, module_test, events):
        web_parameter_emitted = False
        tag_attribute_xss_emitted = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [path]" in e.data["description"]:
                    web_parameter_emitted = True
            if e.type == "FINDING":
                if "Possible Reflected XSS" in e.data["description"] and "Tag Attribute" in e.data["description"]:
                    tag_attribute_xss_emitted = True

        assert web_parameter_emitted, "WEB_PARAMETER was not emitted"
        assert not tag_attribute_xss_emitted, (
            "Tag Attribute XSS should NOT be reported when the quote only survives in text content, not in tag attributes"
        )


# SQLi WAF False Positive (Akamai-style 403)
class Test_Lightfuzz_sqli_waf(Test_Lightfuzz_sqli):
    """SQLi negative test: endpoint returns 403 with WAF signature when single quote is sent.
    Should NOT report SQL injection."""

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

            if value.endswith("'") and not value.endswith("''"):
                # WAF blocks the request with a known WAF string
                waf_response = """
                <html>
                <head><title>Access Denied</title></head>
                <body>
                <h1>Access Denied</h1>
                <p>The requested URL was rejected. Please consult with your administrator.</p>
                </body>
                </html>
                """
                return Response(waf_response, status=403)
            return Response(parameter_block, status=200)
        return Response(parameter_block, status=200)

    def check(self, module_test, events):
        web_parameter_emitted = False
        sqli_finding_emitted = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [search]" in e.data["description"]:
                    web_parameter_emitted = True
            if e.type == "FINDING":
                if "Possible SQL Injection" in e.data["description"] and "Code Change" in e.data["description"]:
                    sqli_finding_emitted = True

        assert web_parameter_emitted, "WEB_PARAMETER was not emitted"
        assert not sqli_finding_emitted, (
            "SQLi should NOT be reported when single quote probe triggers a WAF 403 response"
        )


# SQLi flappy baseline: server alternates between status codes across rounds.
# The confirmation loop should detect the instability and suppress the finding.
class Test_Lightfuzz_sqli_flappy_baseline(Test_Lightfuzz_sqli):
    """SQLi negative test: server flaps between 200 and 303 across requests.
    The confirmation loop should detect unstable baselines and suppress the finding."""

    request_count = 0

    def request_handler(self, request):
        self.__class__.request_count += 1
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

            # First round: return the classic 200->500->200 pattern to trigger initial detection
            # Subsequent rounds: flap baseline to 303 to simulate CDN instability
            if self.__class__.request_count > 12:
                # After initial probes, start flapping the baseline
                return Response("Redirecting", status=303, headers={"Location": "/"})

            if value.endswith("'"):
                if value.endswith("''"):
                    return Response("<p>normal</p>", status=200)
                return Response("<p>error</p>", status=500)
        return Response(parameter_block, status=200)

    def check(self, module_test, events):
        web_parameter_emitted = False
        sqli_finding_emitted = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [search]" in e.data["description"]:
                    web_parameter_emitted = True
            if e.type == "FINDING":
                if "Possible SQL Injection" in e.data["description"] and "Code Change" in e.data["description"]:
                    sqli_finding_emitted = True

        assert web_parameter_emitted, "WEB_PARAMETER was not emitted"
        assert not sqli_finding_emitted, (
            "SQLi code-change finding should NOT be emitted when baseline is flappy across confirmation rounds"
        )


# Verify that POST SQLi findings include additional_params in the description
class Test_Lightfuzz_sqli_post_additional_params(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["http", "lightfuzz", "excavate"]
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
                <input type=text name=search>
                <input type=hidden name=form_id value=search_form>
                <button type=submit>Search</button>
            </form>
        </section>
        """
        if "search" in request.form.keys():
            value = request.form["search"]
            if value.endswith("'"):
                if value.endswith("''"):
                    return Response("<p>normal</p>", status=200)
                return Response("<p>error</p>", status=500)
            return Response("<p>results</p>", status=200)
        return Response(parameter_block, status=200)

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["lightfuzz"].helpers.rand_string = lambda *args, **kwargs: (
            "1234567890" if kwargs.get("numeric_only") else "AAAAAAAAAAAAAA"
        )
        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

    def check(self, module_test, events):
        sqli_finding_emitted = False
        for e in events:
            if e.type == "FINDING" and "Code Change" in e.data.get("description", ""):
                desc = e.data["description"]
                if "POSTPARAM" in desc:
                    # POST findings should include additional_params info
                    assert "Additional Params:" in desc, f"POST finding description missing additional_params: {desc}"
                    sqli_finding_emitted = True
        assert sqli_finding_emitted, "SQLi POST code-change FINDING not emitted"


# Verify that lightfuzz rejects WEB_PARAMETER events on static-asset URLs (.pdf, .xml, etc.)
class Test_Lightfuzz_static_url_filter(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["http", "lightfuzz", "excavate"]
    config_overrides = {
        "interactsh_disable": True,
        "modules": {
            "lightfuzz": {
                "enabled_submodules": ["sqli"],
            }
        },
    }

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["lightfuzz"].helpers.rand_string = lambda *args, **kwargs: (
            "1234567890" if kwargs.get("numeric_only") else "AAAAAAAAAAAAAA"
        )
        respond_args = {"response_data": "<html><body>placeholder</body></html>", "status": 200}
        expect_args = {"method": "GET", "uri": "/"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # Inject a WEB_PARAMETER event on a .pdf URL
        seed_events = []
        parent_event = module_test.scan.make_event(
            "http://127.0.0.1:8888/",
            "URL",
            module_test.scan.root_event,
            module="http",
            tags=["status-200", "distance-0"],
        )
        data = {
            "host": "127.0.0.1",
            "type": "GETPARAM",
            "name": "v",
            "original_value": "1",
            "url": "http://127.0.0.1:8888/document.pdf?v=1",
            "description": "HTTP Extracted Parameter [v]",
        }
        seed_event = module_test.scan.make_event(data, "WEB_PARAMETER", parent_event, tags=["distance-0"])
        seed_events.append(seed_event)
        for event in seed_events:
            await module_test.scan.ingress_module.incoming_event_queue.put(event)

    def check(self, module_test, events):
        sqli_finding_emitted = False
        for e in events:
            if e.type == "FINDING":
                if "Possible SQL Injection" in e.data["description"]:
                    sqli_finding_emitted = True

        assert not sqli_finding_emitted, (
            "SQLi finding should NOT be emitted for WEB_PARAMETER on a static-asset URL (.pdf)"
        )
