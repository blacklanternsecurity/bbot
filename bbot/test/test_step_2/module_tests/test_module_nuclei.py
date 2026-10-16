from ...bbot_fixtures import *
from .base import ModuleTestBase
from bbot.test.worker import HTTPSERVER_URL, BBOT_TEST_DIR, BBOT_TEST_TOOLS_DIR

import copy
import fcntl
from types import SimpleNamespace
from unittest.mock import patch


class TestNucleiManual(ModuleTestBase):
    targets = [HTTPSERVER_URL]
    modules_overrides = ["http", "excavate", "nuclei"]
    config_overrides = {
        "web": {
            "spider_distance": 1,
            "spider_depth": 1,
        },
        "interactsh_disable": True,
        "modules": {
            "nuclei": {
                "mode": "manual",
                "concurrency": 2,
                "templates": f"{BBOT_TEST_TOOLS_DIR}/nuclei-state/templates/http/miscellaneous/",
                "directory_only": False,
            }
        },
    }

    test_html = f"""
    html>
 <head>
  <title>Index of /test</title>
 </head>
 <body>
<h1>Index of /test</h1>
  <table>
   <tr><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th><th><a href="?C=S;O=A">Size</a></th></tr>
   <tr><th colspan="3"><hr></th></tr>
<tr><td><a href="/">Parent Directory</a></td><td>&nbsp;</td><td align="right">  - </td></tr>
</table>
<address>Apache/2.4.38 (Debian) Server at {HTTPSERVER_URL}/testmultipleruns.html</address>
</body></html>
"""

    async def setup_after_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": self.test_html}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)
        expect_args = {"method": "GET", "uri": "/testmultipleruns.html"}
        respond_args = {"response_data": "<html>Copyright 1984</html>"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        first_run_detect = False
        second_run_detect = False
        for e in events:
            if e.type == "FINDING":
                if "Directory listing enabled" in e.data["description"]:
                    first_run_detect = True
                    # Nuclei emits HIGH confidence for most findings
                    assert e.data["confidence"] == "HIGH"
                elif "Copyright" in e.data["description"]:
                    second_run_detect = True
                    assert e.data["confidence"] == "HIGH"
        assert first_run_detect
        assert second_run_detect


class TestNucleiSevere(TestNucleiManual):
    modules_overrides = ["http", "nuclei"]
    config_overrides = {
        "modules": {
            "nuclei": {
                "mode": "severe",
                "concurrency": 1,
                "templates": f"{BBOT_TEST_TOOLS_DIR}/nuclei-state/templates/http/vulnerabilities/generic/generic-env.yaml",
            }
        },
        "interactsh_disable": True,
    }

    async def setup_after_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/.env"}
        respond_args = {"response_data": "AAAKEYBBB="}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "<html>alive</html>"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        assert any(e.type == "FINDING" and "Generic Env File Disclosure" in e.data["description"] for e in events)


class TestNucleiTechnology(TestNucleiManual):
    # etypes tcp: the fixture is a single HTTP port, so tcp-protocol templates
    # (cassandra 9042, kafka 9092, ajp 8009) can only ever dial a closed port and
    # wait out nuclei's fixed 5s read timeout. They match nothing here.
    config_overrides = {
        "web": {"http_timeout": 7},
        "interactsh_disable": True,
        "modules": {"nuclei": {"mode": "technology", "concurrency": 2, "tags": "apache", "etypes": "tcp"}},
    }

    async def setup_before_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {
            "response_data": "<html><Directory></Directory></html>",
            "headers": {"Server": "Apache/2.4.52 (Ubuntu)"},
        }
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    async def setup_after_prep(self, module_test):
        self.commands = []
        module = module_test.scan.modules["nuclei"]
        original = module.run_process_live

        def capture(*args, **kwargs):
            command = args[0] if args and isinstance(args[0], (list, tuple)) else args
            self.commands.append([str(c) for c in command])
            return original(*args, **kwargs)

        module.run_process_live = capture

    def check(self, module_test, events):
        assert any(e.type == "TECHNOLOGY" and "apache" in e.data["technology"].lower() for e in events)
        assert "Using Interactsh Server" not in open(module_test.scan.home / "debug.log").read()

        assert self.commands, "nuclei was never executed"
        for command in self.commands:
            assert "-exclude-type" in command, f"-exclude-type missing from {command}"
            assert command[command.index("-exclude-type") + 1] == "tcp"
            # nuclei silently defaults to its own 10s, so an unpassed -timeout
            # means web.http_timeout is ignored by this module alone
            assert "-timeout" in command, f"-timeout missing from {command}"
            assert command[command.index("-timeout") + 1] == "7"


class TestNucleiBudget(TestNucleiManual):
    config_overrides = {
        "interactsh_disable": True,
        "modules": {
            "nuclei": {
                "mode": "budget",
                "concurrency": 1,
                "tags": "spiderfoot",
                "templates": f"{BBOT_TEST_TOOLS_DIR}/nuclei-state/templates/exposed-panels/spiderfoot.yaml",
            }
        },
    }

    async def setup_before_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "<html><title>SpiderFoot</title><p>support@spiderfoot.net</p></html>"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        assert any(e.type == "TECHNOLOGY" and "spider" in e.data["technology"] for e in events)


class TestNucleiRetries(TestNucleiManual):
    config_overrides = {
        "interactsh_disable": True,
        "modules": {"nuclei": {"tags": "musictraveler"}},
    }

    async def setup_before_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {
            "response_data": "content",
        }
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        assert "-retries 0" in open(module_test.scan.home / "debug.log").read()


class TestNucleiRetriesCustom(TestNucleiRetries):
    config_overrides = {
        "interactsh_disable": True,
        "modules": {"nuclei": {"tags": "musictraveler", "retries": 1}},
    }

    def check(self, module_test, events):
        assert "-retries 1" in open(module_test.scan.home / "debug.log").read()


class TestNucleiEnvIsolation(TestNucleiManual):
    """Set hostile env vars before the scan and verify _nuclei_env() filters them out.

    The base TestNucleiManual assertions double as a regression check: nuclei must
    still find and run templates even when the user's env has DISABLE_*_DOWNLOAD,
    XDG_CONFIG_HOME, etc. set.
    """

    leaky_env = {
        "PDCP_API_KEY": "user-pdcp-key-must-not-leak",
        "PDCP_TEAM_ID": "user-team",
        "XDG_CONFIG_HOME": f"{BBOT_TEST_DIR}/xdg-leak-config",
        "XDG_CACHE_HOME": f"{BBOT_TEST_DIR}/xdg-leak-cache",
        "GITHUB_TOKEN": "ghp_usertoken",
        "GITHUB_TEMPLATE_REPO": "attacker/private-templates",
        "GITLAB_TOKEN": "glpat-usertoken",
        "AWS_ACCESS_KEY": "AKIA-user",
        "AWS_SECRET_KEY": "user-aws-secret",
        "AZURE_CLIENT_SECRET": "azure-secret",
        "NUCLEI_SIGNATURE_PUBLIC_KEY": "user-pubkey",
        "DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD": "true",
    }

    async def setup_before_prep(self, module_test):
        await super().setup_before_prep(module_test)
        for k, v in self.leaky_env.items():
            module_test.monkeypatch.setenv(k, v)

    # XDG_{CONFIG,CACHE}_HOME are set by _nuclei_env() itself to our paths,
    # so they appear in env but must override (not echo back) the user's values.
    _xdg_overridden = {"XDG_CONFIG_HOME", "XDG_CACHE_HOME"}

    def check(self, module_test, events):
        super().check(module_test, events)
        nuclei = module_test.scan.modules["nuclei"]
        env = nuclei._nuclei_env()
        for k, v in self.leaky_env.items():
            if k in self._xdg_overridden:
                assert env.get(k) != v, f"{k} leaked user value into nuclei env"
            else:
                assert k not in env, f"{k} leaked into nuclei subprocess env"
        assert env["XDG_CONFIG_HOME"] == str(nuclei.nuclei_config_dir)
        assert env["XDG_CACHE_HOME"] == str(nuclei.nuclei_cache_dir)
        # HOME is intentionally NOT forwarded — nuclei must rely on the XDG
        # vars we set, not on the user's home dir.
        assert "HOME" not in env


def test_nuclei_classify_update_stderr():
    """Regression: nuclei's success line has changed wording across releases
    ("downloaded" → "installed" → "updated"). All three must classify as
    success so a fresh install isn't mis-logged as a failure.
    """
    from bbot.modules.nuclei import nuclei

    c = nuclei._classify_update_stderr
    # First-time install (what nuclei v3.8 prints on a clean state dir).
    assert (
        c(
            "[INF] nuclei-templates are not installed, installing...\n[INF] Successfully installed nuclei-templates at /tmp/x"
        )
        == "updated"
    )
    # Version bump (newer phrasing).
    assert c("[INF] Successfully updated nuclei-templates (v10.4.3) to /tmp/x. GoodLuck!") == "updated"
    # Legacy phrasing — kept for older nuclei builds.
    assert c("[INF] Successfully downloaded nuclei-templates") == "updated"
    # Already up-to-date.
    assert c("[INF] No new updates found for nuclei templates") == "up-to-date"
    # Benign first-run noise must NOT trick us into reporting success.
    assert c("[ERR] Could not copy nuclei ignore file ...: source file doesn't exist") == "failure"
    # Empty / None stderr → failure (process produced nothing).
    assert c("") == "failure"
    assert c(None) == "failure"


@pytest.mark.asyncio
async def test_nuclei_repair_wipe_holds_the_lock(tmp_path):
    """Regression: the corruption repair wipes the whole nuclei state dir. If it
    runs outside the template lock, a worker that wipes while another is
    mid-extract destroys the other's output, so both fail and every nuclei test
    on every xdist worker hard-fails with "Failed to install nuclei templates
    after retry". Pin that the wipe only happens while the lock is held.
    """
    from bbot.modules.nuclei import nuclei

    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    state_dir = tools_dir / "nuclei-state"
    templates_dir = state_dir / "templates"

    mod = nuclei.__new__(nuclei)
    mod.nuclei_state_dir = state_dir
    mod.nuclei_config_dir = state_dir / "config"
    mod.nuclei_cache_dir = state_dir / "cache"
    mod.nuclei_templates_dir = templates_dir
    mod.nuclei_config_dir.mkdir(parents=True, exist_ok=True)
    mod.nuclei_cache_dir.mkdir(parents=True, exist_ok=True)

    helpers = SimpleNamespace(
        tools_dir=tools_dir,
        run_in_executor_io=lambda fn, *a: asyncio.get_running_loop().run_in_executor(None, fn, *a),
    )
    for name in ("info", "warning", "success", "debug"):
        setattr(mod, name, lambda *a, **kw: None)

    held_during_wipe = []
    original_rmtree = shutil.rmtree

    def probe_rmtree(path, *args, **kwargs):
        # a second process must not be able to take the lock while we wipe
        probe = open(tools_dir / "nuclei-templates.lock", "w")
        try:
            try:
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                held_during_wipe.append(False)
                fcntl.flock(probe, fcntl.LOCK_UN)
            except OSError:
                held_during_wipe.append(True)
        finally:
            probe.close()
        return original_rmtree(path, *args, **kwargs)

    # first update produces nothing (simulates the killed/incomplete extract),
    # second one populates the tree so the repair path is exercised end to end
    calls = []

    async def fake_update():
        calls.append(1)
        if len(calls) > 1:
            (templates_dir / "http").mkdir(parents=True, exist_ok=True)
            (templates_dir / "http" / "t.yaml").write_text("id: t")
        # claimed success but produced nothing: the stale-marker corruption the
        # wipe exists to repair
        return "updated"

    mod._run_template_update = fake_update

    with patch.object(shutil, "rmtree", probe_rmtree), patch.object(nuclei, "helpers", helpers):
        installed = await mod._ensure_templates()

    assert installed, "repair path should report success once templates land"
    assert calls == [1, 1], "repair should run exactly one retry update"
    assert held_during_wipe == [True], "state dir was wiped without holding the template lock"
    # lock must be released afterwards so the next worker can proceed
    after = open(tools_dir / "nuclei-templates.lock", "w")
    try:
        fcntl.flock(after, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(after, fcntl.LOCK_UN)
    finally:
        after.close()


@pytest.mark.asyncio
async def test_nuclei_failed_download_does_not_wipe_and_refetch(tmp_path):
    """Regression: when the template download itself fails, nuclei produced no
    files, so there is no stale-marker corruption to repair. Wiping and
    re-downloading doubles the requests against an already-failing source. In CI
    this turned one bad fetch into 66 downloads and 33 hard failures across every
    xdist worker. A "failure" outcome must fail fast without a second fetch.
    """
    from bbot.modules.nuclei import nuclei

    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    state_dir = tools_dir / "nuclei-state"

    mod = nuclei.__new__(nuclei)
    mod.nuclei_state_dir = state_dir
    mod.nuclei_config_dir = state_dir / "config"
    mod.nuclei_cache_dir = state_dir / "cache"
    mod.nuclei_templates_dir = state_dir / "templates"
    mod.nuclei_config_dir.mkdir(parents=True, exist_ok=True)
    mod.nuclei_cache_dir.mkdir(parents=True, exist_ok=True)

    helpers = SimpleNamespace(
        tools_dir=tools_dir,
        run_in_executor_io=lambda fn, *a: asyncio.get_running_loop().run_in_executor(None, fn, *a),
    )
    for name in ("info", "warning", "success", "debug"):
        setattr(mod, name, lambda *a, **kw: None)

    calls = []
    wiped = []

    async def failing_update():
        calls.append(1)
        return "failure"

    mod._run_template_update = failing_update

    with patch.object(shutil, "rmtree", lambda *a, **kw: wiped.append(1)), patch.object(nuclei, "helpers", helpers):
        installed = await mod._ensure_templates()

    assert installed is False, "a failed download must not report success"
    assert calls == [1], "a failed download must not trigger a second fetch"
    assert wiped == [], "a failed download must not wipe state that holds no corruption"


class TestNucleiCustomHeaders(TestNucleiManual):
    custom_headers = {"testheader1": "test1", "testheader2": "test2"}
    # deep copy: a shallow dict() still shares the nested "web" dict, so writing
    # http_headers into it would reach TestNucleiManual and every sibling subclass.
    config_overrides = copy.deepcopy(TestNucleiManual.config_overrides)
    config_overrides["web"]["http_headers"] = custom_headers

    async def setup_after_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/", "headers": self.custom_headers}
        respond_args = {"response_data": self.test_html}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)
        expect_args = {"method": "GET", "uri": "/testmultipleruns.html", "headers": {"nonexistent": "nope"}}
        respond_args = {"response_data": "<html>Copyright 1984</html>"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        first_run_detect = False
        second_run_detect = False
        for e in events:
            if e.type == "FINDING":
                if "Directory listing enabled" in e.data["description"]:
                    first_run_detect = True
                elif "Copyright" in e.data["description"]:
                    second_run_detect = True
        # we should find the first one because it requires our custom headers
        assert first_run_detect
        # the second one requires different headers, so we shouldn't find it
        assert not second_run_detect
