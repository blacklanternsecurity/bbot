import pytest
import asyncio
import logging
import pytest_asyncio
from omegaconf import OmegaConf

from ...bbot_fixtures import *
from bbot.scanner import Scanner
from bbot.core.helpers.misc import rand_string

log = logging.getLogger("bbot.test.modules")


def tempwordlist(content):
    from bbot.core.helpers.misc import rand_string

    filename = bbot_test_dir / f"{rand_string(8)}"
    with open(filename, "w", errors="ignore") as f:
        for c in content:
            line = f"{c}\n"
            f.write(line)
    return filename


class ModuleTestBase:
    targets = ["blacklanternsecurity.com"]
    scan_name = None
    blacklist = None
    whitelist = None
    module_name = None
    config_overrides = {}
    modules_overrides = None
    log = logging.getLogger("bbot")

    class ModuleTest:
        def __init__(
            self, module_test_base, httpx_mock, httpserver, httpserver_ssl, monkeypatch, request, caplog, capsys
        ):
            self.name = module_test_base.name
            self.config = OmegaConf.merge(CORE.config, OmegaConf.create(module_test_base.config_overrides))

            self.caplog = caplog
            self.capsys = capsys

            self.httpx_mock = httpx_mock
            self.httpserver = httpserver
            self.httpserver_ssl = httpserver_ssl
            self.monkeypatch = monkeypatch
            self.request_fixture = request
            self.preloaded = DEFAULT_PRESET.module_loader.preloaded()

            # handle output, internal module types
            output_modules = None
            modules = list(module_test_base.modules)
            output_modules = ["python"]
            for module in list(modules):
                module_type = self.preloaded[module]["type"]
                if module_type in ("internal", "output"):
                    modules.remove(module)
                    if module_type == "output":
                        output_modules.append(module)
                    elif module_type == "internal" and not module == "dnsresolve":
                        self.config = OmegaConf.merge(self.config, {module: True})

            self.scan = Scanner(
                *module_test_base.targets,
                modules=modules,
                output_modules=output_modules,
                scan_name=module_test_base._scan_name,
                config=self.config,
                whitelist=module_test_base.whitelist,
                blacklist=module_test_base.blacklist,
            )
            self.events = []
            self.log = logging.getLogger(f"bbot.test.{module_test_base.name}")

        def set_expect_requests(self, expect_args={}, respond_args={}):
            if "uri" not in expect_args:
                expect_args["uri"] = "/"
            self.httpserver.expect_request(**expect_args).respond_with_data(**respond_args)

        def set_expect_requests_handler(self, expect_args=None, request_handler=None):
            self.httpserver.expect_request(expect_args).respond_with_handler(request_handler)

        async def mock_dns(self, mock_data, scan=None):
            if scan is None:
                scan = self.scan
            await scan.helpers.dns._mock_dns(mock_data)

        def mock_interactsh(self, name):
            from ...conftest import Interactsh_mock

            return Interactsh_mock(name)

        @property
        def module(self):
            return self.scan.modules[self.name]

    @pytest_asyncio.fixture
    async def module_test(
        self, httpx_mock, bbot_httpserver, bbot_httpserver_ssl, monkeypatch, request, caplog, capsys
    ):
        self.log.info(f"Starting {self.name} module test")
        module_test = self.ModuleTest(
            self, httpx_mock, bbot_httpserver, bbot_httpserver_ssl, monkeypatch, request, caplog, capsys
        )
        self.log.debug(f"Mocking DNS")
        await module_test.mock_dns({"blacklanternsecurity.com": {"A": ["127.0.0.88"]}})
        self.log.debug(f"Executing setup_before_prep()")
        await self.setup_before_prep(module_test)
        self.log.debug(f"Executing scan._prep()")
        await module_test.scan._prep()
        self.log.debug(f"Executing setup_after_prep()")
        await self.setup_after_prep(module_test)
        self.log.debug(f"Starting scan")
        module_test.events = [e async for e in module_test.scan.async_start()]
        self.log.debug(f"Finished {module_test.name} module test")
        yield module_test

    @pytest.mark.asyncio
    async def test_module_run(self, module_test):
        self.check(module_test, module_test.events)
        module_test.log.info(f"Finished {self.name} module test")
        current_task = asyncio.current_task()
        tasks = [t for t in asyncio.all_tasks() if t != current_task]
        if len(tasks):
            module_test.log.info(f"Unfinished tasks detected: {tasks}")
        else:
            module_test.log.info(f"No unfinished tasks detected")

    def check(self, module_test, events):
        assert False, f"Must override {self.name}.check()"

    @property
    def name(self):
        if self.module_name is not None:
            return self.module_name
        return self.__class__.__name__.split("Test")[-1].lower()

    @property
    def _scan_name(self):
        if self.scan_name:
            return self.scan_name
        if getattr(self, "__scan_name", None) is None:
            self.__scan_name = f"{self.__class__.__name__.lower()}_test_{rand_string()}"
        return self.__scan_name

    @property
    def modules(self):
        if self.modules_overrides is not None:
            return self.modules_overrides
        return [self.name]

    async def setup_before_prep(self, module_test):
        pass

    async def setup_after_prep(self, module_test):
        pass
