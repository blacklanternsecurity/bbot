# Unit Tests

BBOT takes tests seriously. Every module *must* have a custom-written test that *actually tests* its functionality. Don't worry if you want to contribute but you aren't used to writing tests. If you open a draft PR, we will help write them :)

We use [ruff](https://docs.astral.sh/ruff/) for linting, and [pytest](https://docs.pytest.org/en/8.2.x/) for tests.

## Running tests locally

We have GitHub Actions that automatically run tests whenever you open a Pull Request. However, you can also run the tests locally with `pytest`:

```bash
# lint with ruff
uv run ruff check

# format code with ruff
uv run ruff format

# run all tests with pytest (takes roughly 30 minutes)
uv run pytest
```

### Running specific tests

If you only want to run a single test, you can select it with `-k`:

```bash
# run only the sslcert test
uv run pytest -k test_module_sslcert
```

You can also filter like this:
```bash
# run all the module tests except for sslcert
uv run pytest -k "test_module_ and not test_module_sslcert"
```

If you want to see the output of your module, you can enable `--log-cli-level`:
```bash
uv run pytest --log-cli-level=DEBUG
```

## Example: Writing a Module Test

To write a test for your module, create a new python file in `bbot/test/test_step_2/module_tests`. Your filename must be `test_module_<module_name>`:

```python title="test_module_mymodule.py"
from .base import ModuleTestBase


class TestMyModule(ModuleTestBase):
    targets = ["blacklanternsecurity.com"]
    config_overrides = {"modules": {"mymodule": {"api_key": "deadbeef"}}}

    async def setup_after_prep(self, module_test):
        # mock HTTP response
        module_test.blasthttp_mock.add_response(
            url="https://api.com/subdomains?apikey=deadbeef&domain=blacklanternsecurity.com",
            json={
                "subdomains": [
                    "www.blacklanternsecurity.com",
                    "dev.blacklanternsecurity.com"
                ],
            },
        )
        # mock DNS
        await module_test.mock_dns(
            {
                "blacklanternsecurity.com": {"A": ["1.2.3.4"]},
                "www.blacklanternsecurity.com": {"A": ["1.2.3.4"]},
                "dev.blacklanternsecurity.com": {"A": ["1.2.3.4"]},
            }
        )

    def check(self, module_test, events):
        # here is where we check to make sure it worked
        dns_names = [e.data for e in events if e.type == "DNS_NAME"]
        # temporary log messages for debugging
        for e in dns_names:
            self.log.critical(e)
        assert "www.blacklanternsecurity.com" in dns_names, "failed to find subdomain #1"
        assert "dev.blacklanternsecurity.com" in dns_names, "failed to find subdomain #2"
```

### Mocking HTTP responses

`module_test.blasthttp_mock` intercepts all outbound HTTP requests during tests. Requests to `127.0.0.1`/`localhost` pass through to the real test HTTP server, but everything else is mocked.

```python
    async def setup_after_prep(self, module_test):
        # JSON response
        module_test.blasthttp_mock.add_response(
            url="https://api.example.com/lookup?domain=blacklanternsecurity.com",
            json={"subdomains": ["www.blacklanternsecurity.com"]},
        )

        # plain text response
        module_test.blasthttp_mock.add_response(
            url="https://example.com/data.txt",
            text="some plain text response",
        )

        # error response
        module_test.blasthttp_mock.add_response(
            url="https://example.com/broken",
            status_code=500,
            text="Internal Server Error",
        )

        # match on specific method and headers
        module_test.blasthttp_mock.add_response(
            url="https://api.example.com/submit",
            method="POST",
            match_headers={"Authorization": "Bearer mytoken"},
            json={"status": "ok"},
        )
```

### Mocking DNS

Use `module_test.mock_dns()` to control DNS resolution. Supports A, AAAA, CNAME, MX, TXT, and other record types:

```python
    async def setup_after_prep(self, module_test):
        await module_test.mock_dns({
            "blacklanternsecurity.com": {"A": ["127.0.0.88"]},
            "www.blacklanternsecurity.com": {"CNAME": ["blacklanternsecurity.com"]},
            "mail.blacklanternsecurity.com": {"MX": ["mx.example.com"]},
        })
```

### Debugging a test

You can debug from within a test using standard Python logging via `self.log`:

```python
    def check(self, module_test, events):
        for e in events:
            self.log.critical(e.type)     # bright red
            self.log.warning(e.tags)      # orange
            self.log.info(e.data)         # blue
            self.log.debug(e.parent)      # grey (requires -d)
```

### Advanced test features

#### HTTP request handlers

For dynamic HTTP responses, use `set_expect_requests_handler` with a custom handler function:

```python
import re
from werkzeug.wrappers import Response

class TestMyModule(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["http", "mymodule"]

    def request_handler(self, request):
        if request.path == "/api/data":
            return Response('{"results": ["found"]}', status=200)
        return Response("Not Found", status=404)

    async def setup_before_prep(self, module_test):
        module_test.set_expect_requests_handler(
            expect_args=re.compile("/.*"),
            request_handler=self.request_handler,
        )
```

#### OOB interaction mocking

For modules that use out-of-band interactions (interactsh):

```python
    async def setup_before_prep(self, module_test):
        self.interactsh_mock_instance = module_test.mock_interactsh("mymodule")

        from bbot.core.helpers.helper import ConfigAwareHelper
        module_test.monkeypatch.setattr(
            ConfigAwareHelper, "interactsh",
            lambda *a, **kw: self.interactsh_mock_instance,
        )
```

#### Other class attributes

```python
class TestMyModule(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]   # override default target
    modules_overrides = ["http", "mymodule"]  # control which modules are enabled
    module_name = "mymodule"               # if your class name doesn't match the module
    config_overrides = {"modules": {"mymodule": {"option": "value"}}}
    blacklist = ["bad.example.com"]        # set a blacklist
    seeds = ["seed.example.com"]           # set seeds separate from targets
    skip_distro_tests = True               # skip when running in CI distro tests (e.g. docker-dependent tests)
```

### More examples

If you have questions about tests or need to write a more advanced test, come talk to us on [GitHub](https://github.com/blacklanternsecurity/bbot/discussions) or [Discord](https://discord.com/invite/PZqkgxu5SA).

It's also a good idea to look through our [existing tests](https://github.com/blacklanternsecurity/bbot/tree/dev/bbot/test/test_step_2/module_tests). BBOT has over 300 of them, so you might find one that's similar to what you're trying to do.
