import logging
from abc import abstractmethod
from omegaconf import OmegaConf

log = logging.getLogger("bbot.test.helpers")


class MockHelper:
    targets = ["blacklanternsecurity.com"]
    blacklist = None
    whitelist = None
    config_overrides = {}
    additional_modules = []

    def __init__(self, request, **kwargs):
        self.name = kwargs.get("module_name", self.__class__.__name__.lower())
        self.bbot_config = request.getfixturevalue("bbot_config")
        self.bbot_scanner = request.getfixturevalue("bbot_scanner")
        self.config = OmegaConf.merge(self.bbot_config, OmegaConf.create(self.config_overrides))
        modules = [self.name] + self.additional_modules
        self.scans = []
        self.scan = self.add_scan(
            *self.targets,
            modules=modules,
            name=f"{self.name}_test",
            config=self.config,
            whitelist=self.whitelist,
            blacklist=self.blacklist,
        )

    def add_scan(self, *args, **kwargs):
        scan = self.bbot_scanner(*args, **kwargs)
        self.scans.append(scan)
        return scan

    def setup(self, scan):
        pass

    async def run(self):
        for i, scan in enumerate(self.scans):
            if i == 0:
                self.scan = scan
            await scan.prep()
            self.setup(scan)

        self._after_scan_prep()
        for i, scan in enumerate(self.scans):
            events = [e async for e in scan.start()]
            self.check_events(events)

    @abstractmethod
    def check_events(self, events):
        raise NotImplementedError

    @property
    def module(self):
        return self.scan.modules[self.name]

    def _after_scan_prep(self):
        pass


class RequestMockHelper(MockHelper):
    def __init__(self, request, **kwargs):
        self.httpx_mock = request.getfixturevalue("httpx_mock")
        super().__init__(request, **kwargs)

    @abstractmethod
    def mock_args(self):
        raise NotImplementedError

    def _after_scan_prep(self):
        self.mock_args()


class HttpxMockHelper(MockHelper):
    targets = ["http://127.0.0.1:8888/"]

    def __init__(self, request, **kwargs):
        self.bbot_httpserver = request.getfixturevalue("bbot_httpserver")
        super().__init__(request, **kwargs)

    @abstractmethod
    def mock_args(self):
        raise NotImplementedError

    def set_expect_requests(self, expect_args={}, respond_args={}):
        if "uri" not in expect_args:
            expect_args["uri"] = "/"
        self.bbot_httpserver.expect_request(**expect_args).respond_with_data(**respond_args)

    def _after_scan_prep(self):
        self.mock_args()


def tempwordlist(content):
    tmp_path = "/tmp/.bbot_test/"
    from bbot.core.helpers.misc import rand_string, mkdir

    mkdir(tmp_path)
    filename = f"{tmp_path}{rand_string(8)}"
    with open(filename, "w", errors="ignore") as f:
        for c in content:
            line = f"{c}\n"
            f.write(line)
    return filename
