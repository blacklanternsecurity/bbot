from .base import ModuleTestBase, tempwordlist
from werkzeug.wrappers import Response
import re

from .test_module_paramminer_getparams import TestParamminer_Getparams
from .test_module_paramminer_headers import helper


class TestReflected_parameters_fromexcavate(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "reflected_parameters", "excavate"]

    def request_handler(self, request):
        normal_block = '<html><a href="/?reflected=foo">foo</a></html>'
        qs = str(request.query_string.decode())
        if "reflected=" in qs:
            value = qs.split("=")[1]
            if "&" in value:
                value = value.split("&")[0]
            reflected_block = f'<html><a href="/?reflected={value}"></a></html>'
            return Response(reflected_block, status=200)
        else:
            return Response(normal_block, status=200)

    async def setup_after_prep(self, module_test):
        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

    def check(self, module_test, events):
        assert any(
            e.type == "FINDING"
            and e.data["description"]
            == "[GETPARAM] Parameter value reflected in response body. Name: [reflected] Source Module: [excavate] Original Value: [foo]"
            for e in events
        )


class TestReflected_parameters_headers(TestReflected_parameters_fromexcavate):
    modules_overrides = ["httpx", "reflected_parameters", "excavate", "paramminer_headers"]
    config_overrides = {
        "modules": {
            "paramminer_headers": {"wordlist": tempwordlist(["junkword1", "tracestate"]), "recycle_words": True}
        }
    }

    def request_handler(self, request):
        headers = {k.lower(): v for k, v in request.headers.items()}
        if "tracestate" in headers:
            reflected_value = headers["tracestate"]
            reflected_block = f"<html><div>{reflected_value}</div></html>"
            return Response(reflected_block, status=200)
        else:
            return Response("<html><div></div></html>", status=200)

    def check(self, module_test, events):
        assert any(
            e.type == "FINDING"
            and e.data["description"]
            == "[HEADER] Parameter value reflected in response body. Name: [tracestate] Source Module: [paramminer_headers]"
            for e in events
        )


class TestReflected_parameters_fromparamminer(TestParamminer_Getparams):
    modules_overrides = ["httpx", "paramminer_getparams", "reflected_parameters"]

    def request_handler(self, request):
        normal_block = "<html></html>"
        qs = str(request.query_string.decode())
        if "id=" in qs:
            value = qs.split("=")[1]
            if "&" in value:
                value = value.split("&")[0]
            reflected_block = f'<html><a href="/?id={value}"></a></html>'
            return Response(reflected_block, status=200)
        else:
            return Response(normal_block, status=200)

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["paramminer_getparams"].rand_string = lambda *args, **kwargs: "AAAAAAAAAAAAAA"
        module_test.monkeypatch.setattr(
            helper.HttpCompare, "gen_cache_buster", lambda *args, **kwargs: {"AAAAAA": "1"}
        )

        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

    def check(self, module_test, events):
        assert any(
            e.type == "FINDING"
            and "[GETPARAM] Parameter value reflected in response body. Name: [id] Source Module: [paramminer_getparams]"
            in e.data["description"]
            for e in events
        )


class TestReflected_parameters_with_canary(TestReflected_parameters_fromexcavate):
    def request_handler(self, request):
        normal_block = '<html><a href="/?reflected=foo">foo</a></html>'
        qs = str(request.query_string.decode())
        if qs:
            # Split the query string into key-value pairs
            params = qs.split("&")
            # Construct the reflected block with all parameters
            reflected_block = '<html><a href="/?'
            reflected_block += "&".join(params)
            reflected_block += '"></a></html>'
            return Response(reflected_block, status=200)
        else:
            return Response(normal_block, status=200)

    def check(self, module_test, events):
        # Ensure no findings are emitted when the canary is reflected
        assert not any(e.type == "FINDING" for e in events)


class TestReflected_parameters_cookies(TestReflected_parameters_fromexcavate):
    modules_overrides = ["httpx", "reflected_parameters", "excavate", "paramminer_cookies"]
    config_overrides = {
        "modules": {
            "paramminer_cookies": {"wordlist": tempwordlist(["junkword1", "testcookie"]), "recycle_words": True}
        }
    }

    def request_handler(self, request):
        cookies = request.cookies
        if "testcookie" in cookies:
            reflected_value = cookies["testcookie"]
            reflected_block = f"<html><div>{reflected_value}</div></html>"
            return Response(reflected_block, status=200)
        else:
            return Response("<html><div></div></html>", status=200)

    def check(self, module_test, events):
        assert any(
            e.type == "FINDING"
            and e.data["description"]
            == "[COOKIE] Parameter value reflected in response body. Name: [testcookie] Source Module: [paramminer_cookies]"
            for e in events
        )


class TestReflected_parameters_postparams(TestReflected_parameters_fromexcavate):
    modules_overrides = ["httpx", "reflected_parameters", "excavate"]

    def request_handler(self, request):
        form_data = request.form
        if "testparam" in form_data:
            reflected_value = form_data["testparam"]
            reflected_block = f"<html><div>{reflected_value}</div></html>"
            return Response(reflected_block, status=200)
        else:
            form_html = """
            <html>
                <body>
                    <form action="/" method="post">
                        <input type="text" name="testparam" value="default_value">
                        <input type="submit" value="Submit">
                    </form>
                </body>
            </html>
            """
            return Response(form_html, status=200)

    def check(self, module_test, events):
        assert any(
            e.type == "FINDING"
            and e.data["description"]
            == "[POSTPARAM] Parameter value reflected in response body. Name: [testparam] Source Module: [excavate] Original Value: [default_value]"
            for e in events
        )


class TestReflected_parameters_bodyjson(TestReflected_parameters_fromexcavate):
    modules_overrides = ["httpx", "reflected_parameters", "excavate"]

    def request_handler(self, request):
        # Ensure the request is expecting JSON data
        if request.content_type == "application/json":
            json_data = request.json
            if "username" in json_data:
                reflected_value = json_data["username"]
                reflected_block = f"<html><div>{reflected_value}</div></html>"
                return Response(reflected_block, status=200)
        # Provide an HTML page with a jQuery AJAX call
        jsonajax_extract_html = """
        <html>
        <script>
        function doLogin(e) {
          e.preventDefault();
          var username = $("#usernamefield").val();
          var password = $("#passwordfield").val();
          $.ajax({
            url: '/api/auth',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({ username: username, password: password }),
            success: function (r) {
              window.location.replace("/demo");
            },
            error: function (r) {
              if (r.status == 401) {
                notify("Access denied");
              } else {
                notify(r.responseText);
              }
            }
          });
        }
        </script>
        <form action=/ method=GET><input type=text name="novalue"><button type=submit class=button>Submit</button></form>
        </html>
        """
        return Response(jsonajax_extract_html, status=200)

    async def setup_after_prep(self, module_test):
        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

    def check(self, module_test, events):
        assert any(
            e.type == "FINDING"
            and e.data["description"]
            == "[BODYJSON] Parameter value reflected in response body. Name: [username] Source Module: [excavate]"
            for e in events
        )
