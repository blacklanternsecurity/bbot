# Unit Tests

BBOT takes tests seriously. Every module *must* have a custom-written test that *actually tests* its functionality. Don't worry if you want to contribute but you aren't used to writing tests. If you open a draft PR, we will help write them :)

We use [ruff](https://docs.astral.sh/ruff/) for linting, and [pytest](https://docs.pytest.org/en/8.2.x/) for tests.

## Running tests locally

We have GitHub Actions that automatically run tests whenever you open a Pull Request. However, you can also run the tests locally with `pytest`:

```bash
# lint with ruff
poetry run ruff check

# format code with ruff
poetry run ruff format

# run all tests with pytest (takes roughly 30 minutes)
poetry run pytest
```

### Running specific tests

If you only want to run a single test, you can select it with `-k`:

```bash
# run only the sslcert test
poetry run pytest -k test_module_sslcert
```

You can also filter like this:
```bash
# run all the module tests except for sslcert
poetry run pytest -k "test_module_ and not test_module_sslcert"
```

If you want to see the output of your module, you can enable `--log-cli-level`:
```bash
poetry run pytest --log-cli-level=DEBUG
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
        module_test.httpx_mock.add_response(
            url="https://api.com/sudomains?apikey=deadbeef&domain=blacklanternsecurity.com",
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

### Debugging a test

Similar to debugging from within a module, you can debug from within a test using `self.log.critical()`, etc:

```python
    def check(self, module_test, events):
        for e in events:
            # bright red
            self.log.critical(e.type)
            # bright green
            self.log.hugesuccess(e.data)
            # bright orange
            self.log.hugewarning(e.tags)
            # bright blue
            self.log.hugeinfo(e.parent)
```

### More advanced tests

If you have questions about tests or need to write a more advanced test, come talk to us on [GitHub](https://github.com/blacklanternsecurity/bbot/discussions) or [Discord](https://discord.com/invite/PZqkgxu5SA).

It's also a good idea to look through our [existing tests](https://github.com/blacklanternsecurity/bbot/tree/stable/bbot/test/test_step_2/module_tests). BBOT has over a hundred of them, so you might find one that's similar to what you're trying to do.
