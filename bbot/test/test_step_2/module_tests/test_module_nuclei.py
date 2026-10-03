from ...bbot_fixtures import *
from .base import ModuleTestBase
from bbot.test.worker import HTTPSERVER_URL, BBOT_TEST_DIR


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
                "ratelimit": 10,
                "templates": f"{BBOT_TEST_DIR}/tools/nuclei-state/templates/http/miscellaneous/",
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
                "templates": f"{BBOT_TEST_DIR}/tools/nuclei-state/templates/http/vulnerabilities/generic/generic-env.yaml",
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
    config_overrides = {
        "interactsh_disable": True,
        "modules": {"nuclei": {"mode": "technology", "concurrency": 2, "tags": "apache"}},
    }

    async def setup_before_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {
            "response_data": "<html><Directory></Directory></html>",
            "headers": {"Server": "Apache/2.4.52 (Ubuntu)"},
        }
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        assert any(e.type == "TECHNOLOGY" and "apache" in e.data["technology"].lower() for e in events)
        assert "Using Interactsh Server" not in open(module_test.scan.home / "debug.log").read()


class TestNucleiBudget(TestNucleiManual):
    config_overrides = {
        "interactsh_disable": True,
        "modules": {
            "nuclei": {
                "mode": "budget",
                "concurrency": 1,
                "tags": "spiderfoot",
                "templates": f"{BBOT_TEST_DIR}/tools/nuclei-state/templates/exposed-panels/spiderfoot.yaml",
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


def test_nuclei_budget_selection():
    """Budget mode must only keep templates whose every request block fits inside the budget.

    nuclei runs all of a template's request blocks, so a template that is only partly in-budget
    still costs the requests of its remaining blocks.
    """
    from bbot.modules.nuclei import NucleiBudget

    def clean_block(path):
        return {"paths": [path], "clean": True}

    summary = {
        "a.yaml": {"severity": "high", "has_raw": False, "blocks": [clean_block("{{BaseURL}}")]},
        "b.yaml": {"severity": "info", "has_raw": False, "blocks": [clean_block("{{BaseURL}}")]},
        "c.yaml": {"severity": "info", "has_raw": False, "blocks": [clean_block("{{BaseURL}}/login")]},
        "d.yaml": {"severity": "info", "has_raw": False, "blocks": [clean_block("{{BaseURL}}/login")]},
        # in-budget path, but the block needs custom headers / a non-GET method / redirects,
        # so nuclei can't merge it with anything
        "dirty.yaml": {
            "severity": "info",
            "has_raw": False,
            "blocks": [{"paths": ["{{BaseURL}}"], "clean": False}],
        },
        # one block in budget, one not
        "mixed.yaml": {
            "severity": "info",
            "has_raw": False,
            "blocks": [clean_block("{{BaseURL}}"), clean_block("{{BaseURL}}/expensive")],
        },
        # raw requests are never merged
        "raw.yaml": {"severity": "info", "has_raw": True, "blocks": [clean_block("{{BaseURL}}")]},
    }

    budget_1 = NucleiBudget(summary, 1)
    assert budget_1.budget_paths == {"{{BaseURL}}"}
    assert budget_1.collapsible_templates == ["a.yaml", "b.yaml"]
    assert budget_1.severity_stats == {"high": 1, "info": 1}
    # a severity with no templates reads as zero rather than raising
    assert budget_1.severity_stats["critical"] == 0

    # raising the budget pulls in the next most common path
    budget_2 = NucleiBudget(summary, 2)
    assert budget_2.budget_paths == {"{{BaseURL}}", "{{BaseURL}}/login"}
    assert budget_2.collapsible_templates == ["a.yaml", "b.yaml", "c.yaml", "d.yaml"]

    # with every path in budget, mixed.yaml qualifies but dirty and raw still don't
    budget_all = NucleiBudget(summary, 10)
    assert "mixed.yaml" in budget_all.collapsible_templates
    assert "dirty.yaml" not in budget_all.collapsible_templates
    assert "raw.yaml" not in budget_all.collapsible_templates


class TestNucleiProfile(TestNucleiRetries):
    config_overrides = {
        "interactsh_disable": True,
        "modules": {"nuclei": {"tags": "musictraveler", "profile": "recommended"}},
    }

    def check(self, module_test, events):
        assert "-profile" in open(module_test.scan.home / "debug.log").read()


class TestNucleiNewTemplates(TestNucleiRetries):
    config_overrides = {
        "interactsh_disable": True,
        "modules": {"nuclei": {"tags": "musictraveler", "new_templates": True}},
    }

    def check(self, module_test, events):
        assert "-new-templates" in open(module_test.scan.home / "debug.log").read()


class TestNucleiTemplateCondition(TestNucleiRetries):
    config_overrides = {
        "interactsh_disable": True,
        "modules": {"nuclei": {"tags": "musictraveler", "template_condition": "severity == 'info'"}},
    }

    def check(self, module_test, events):
        assert "-template-condition" in open(module_test.scan.home / "debug.log").read()


class TestNucleiTemplateFilters(TestNucleiRetries):
    """Every straight-passthrough filter option reaches the nuclei command line."""

    config_overrides = {
        "interactsh_disable": True,
        "modules": {
            "nuclei": {
                "tags": "musictraveler",
                "exclude_severity": "info",
                "include_tags": "fuzz",
                "template_ids": "CVE-2024-0012",
                "exclude_ids": "CVE-2021-26855",
                "protocol_types": "http",
            }
        },
    }

    def check(self, module_test, events):
        log = open(module_test.scan.home / "debug.log").read()
        for flag in (
            "-exclude-severity info",
            "-include-tags fuzz",
            "-template-id CVE-2024-0012",
            "-exclude-id CVE-2021-26855",
            "-type http",
        ):
            assert flag in log, f"'{flag}' never reached the nuclei command line"


class TestNucleiEnumDrift(TestNucleiRetries):
    """Pin our hardcoded severity/protocol lists against what the nuclei binary actually accepts.

    Those lists are literals inside the Config validator, because Config bodies are exec'd without
    module globals. A nuclei version bump that adds a value would otherwise make BBOT reject a
    config that nuclei supports, so fail here instead of in the field.
    """

    config_overrides = {
        "interactsh_disable": True,
        "modules": {"nuclei": {"tags": "musictraveler"}},
    }

    def check(self, module_test, events):
        import re
        import subprocess
        from bbot.scanner import Preset

        nuclei_bin = module_test.scan.helpers.tools_dir / "nuclei"
        result = subprocess.run([str(nuclei_bin), "-h"], capture_output=True, text=True)
        help_text = result.stdout + result.stderr

        def advertised(pattern):
            match = re.search(rf"{pattern}.*?Possible values: (.+)", help_text)
            assert match, f"could not find '{pattern}' in nuclei -h; the help format may have changed"
            return [v.strip() for v in match.group(1).split(",") if v.strip()]

        severities = advertised(r"-s, -severity value\[\]")
        protocol_types = advertised(r"-pt, -type value\[\]")
        assert severities and protocol_types

        for option, values in (
            ("severity", severities),
            ("exclude_severity", severities),
            ("protocol_types", protocol_types),
        ):
            for value in values:
                preset = Preset(config={"modules": {"nuclei": {option: value}}})
                # raises ValidationError if nuclei has added a value our validator doesn't know
                preset.validate()

        # and the validator is actually wired up, so the loop above isn't vacuously passing
        with pytest.raises(Exception):
            Preset(config={"modules": {"nuclei": {"severity": "notarealseverity"}}}).validate()


@pytest.mark.asyncio
async def test_nuclei_invalid_profile(caplog):
    """An unknown profile makes nuclei print FTL and exit 0, so the module has to catch it itself."""
    from bbot.errors import ScanError
    from bbot.scanner import Scanner

    scan = Scanner(
        "127.0.0.1",
        modules=["nuclei"],
        config={"interactsh_disable": True, "modules": {"nuclei": {"profile": "definitelynotaprofile"}}},
    )
    with pytest.raises(ScanError):
        await scan._prep()
    assert "Invalid nuclei profile 'definitelynotaprofile'" in caplog.text


@pytest.mark.asyncio
async def test_nuclei_invalid_template_condition(caplog):
    """nuclei treats an unrecognized field as a non-match rather than an error, so zero matching
    templates is the only signal that the expression was wrong."""
    from bbot.errors import ScanError
    from bbot.scanner import Scanner

    scan = Scanner(
        "127.0.0.1",
        modules=["nuclei"],
        config={"interactsh_disable": True, "modules": {"nuclei": {"template_condition": "bogus_field == 1"}}},
    )
    with pytest.raises(ScanError):
        await scan._prep()
    assert "matched 0 templates" in caplog.text


class TestNucleiCustomHeaders(TestNucleiManual):
    custom_headers = {"testheader1": "test1", "testheader2": "test2"}
    config_overrides = TestNucleiManual.config_overrides
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
