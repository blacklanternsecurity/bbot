import ast
import inspect

from baddns.base import get_all_modules
from baddns.lib.findings import SEVERITY_LEVELS, CONFIDENCE_LEVELS

from bbot.modules.baddns import SUBMODULE_MAX_SEVERITY, SUBMODULE_MAX_CONFIDENCE

from .base import ModuleTestBase
from bbot.test.worker import HTTPSERVER_HOSTPORT, HTTPSERVER_PORT


def _extract_finding_values(module_cls):
    """
    AST-parse a baddns submodule and extract all string-literal severity
    and confidence values from Finding() constructor calls.

    Returns (set of severity strings, set of confidence strings).
    """
    # Parse the whole source file rather than inspect.getsource(cls): the
    # latter relies on linecache heuristics that can mis-anchor on Python
    # 3.13+ and return a partial/indented fragment that fails to parse.
    # Each baddns submodule is one class per file, so this is equivalent.
    source_file = inspect.getsourcefile(module_cls)
    with open(source_file) as f:
        source = f.read()
    tree = ast.parse(source)

    severities = set()
    confidences = set()

    for node in ast.walk(tree):
        # Look for Finding({...}) calls
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Name) and func.id == "Finding"):
            continue
        if not node.args:
            continue
        arg = node.args[0]
        if not isinstance(arg, ast.Dict):
            continue
        for key, value in zip(arg.keys, arg.values):
            if not isinstance(key, ast.Constant):
                continue
            if key.value == "severity" and isinstance(value, ast.Constant) and isinstance(value.value, str):
                severities.add(value.value)
            if key.value == "confidence" and isinstance(value, ast.Constant) and isinstance(value.value, str):
                confidences.add(value.value)

    return severities, confidences


def _max_level(values, levels):
    """Return the highest value from `values` according to the ordering in `levels`."""
    if not values:
        return None
    # levels is ordered high-to-low in baddns (CRITICAL, HIGH, MEDIUM, LOW, INFO)
    for level in levels:
        if level in values:
            return level
    return None


# Modules that wrap CNAME findings and may use variables for severity/confidence.
# When a field uses a variable instead of a literal, its max is bounded by
# CNAME's max for that field.
CNAME_DERIVED_MODULES = {"references", "txt", "wildcard", "mtasts"}


def test_baddns_max_severity_confidence():
    """
    Ensure SUBMODULE_MAX_SEVERITY and SUBMODULE_MAX_CONFIDENCE in the BBOT
    baddns module match what the baddns library's source code actually contains.
    """
    all_modules = {cls.name: cls for cls in get_all_modules()}

    # First, compute CNAME's maxes since other modules derive from it
    cname_cls = all_modules.get("CNAME")
    assert cname_cls is not None, "CNAME module not found in baddns"
    cname_sevs, cname_confs = _extract_finding_values(cname_cls)
    cname_max_sev = _max_level(cname_sevs, SEVERITY_LEVELS)
    cname_max_conf = _max_level(cname_confs, CONFIDENCE_LEVELS)

    errors = []

    for name, cls in all_modules.items():
        sevs, confs = _extract_finding_values(cls)

        # For CNAME-derived modules, if no literal severity/confidence was found,
        # the values are inherited from CNAME findings
        if (
            name.lower() in CNAME_DERIVED_MODULES
            or cls.__name__.lower().replace("baddns_", "") in CNAME_DERIVED_MODULES
        ):
            if not sevs and cname_max_sev:
                sevs = {cname_max_sev}
            if not confs and cname_max_conf:
                confs = {cname_max_conf}

        actual_max_sev = _max_level(sevs, SEVERITY_LEVELS)
        actual_max_conf = _max_level(confs, CONFIDENCE_LEVELS)

        expected_sev = SUBMODULE_MAX_SEVERITY.get(name)
        expected_conf = SUBMODULE_MAX_CONFIDENCE.get(name)

        if expected_sev is None and expected_conf is None:
            errors.append(f"Module [{name}] is missing from both SUBMODULE_MAX_SEVERITY and SUBMODULE_MAX_CONFIDENCE")
            continue

        if expected_sev != actual_max_sev:
            errors.append(
                f"Module [{name}] max_severity mismatch: BBOT says {expected_sev}, baddns source says {actual_max_sev}"
            )
        if expected_conf != actual_max_conf:
            errors.append(
                f"Module [{name}] max_confidence mismatch: BBOT says {expected_conf}, baddns source says {actual_max_conf}"
            )

    assert not errors, "BBOT baddns max severity/confidence out of sync with baddns library:\n" + "\n".join(errors)


def test_baddns_submodule_coverage():
    """
    Ensure every baddns submodule is represented in both SUBMODULE_MAX dicts,
    and no stale entries exist for modules that were removed.
    """
    all_module_names = {cls.name for cls in get_all_modules()}
    severity_names = set(SUBMODULE_MAX_SEVERITY.keys())
    confidence_names = set(SUBMODULE_MAX_CONFIDENCE.keys())

    missing_severity = all_module_names - severity_names
    missing_confidence = all_module_names - confidence_names
    stale_severity = severity_names - all_module_names
    stale_confidence = confidence_names - all_module_names

    errors = []
    if missing_severity:
        errors.append(f"Modules missing from SUBMODULE_MAX_SEVERITY: {missing_severity}")
    if missing_confidence:
        errors.append(f"Modules missing from SUBMODULE_MAX_CONFIDENCE: {missing_confidence}")
    if stale_severity:
        errors.append(f"Stale entries in SUBMODULE_MAX_SEVERITY (module removed from baddns): {stale_severity}")
    if stale_confidence:
        errors.append(f"Stale entries in SUBMODULE_MAX_CONFIDENCE (module removed from baddns): {stale_confidence}")

    assert not errors, "\n".join(errors)


class BaseTestBaddns(ModuleTestBase):
    modules_overrides = ["baddns"]
    targets = ["bad.dns"]
    config_overrides = {"dns": {"minimal": False}}

    async def dispatchWHOIS(x):
        return None

    def select_modules(self):
        from baddns.base import get_all_modules

        selected_modules = []
        for m in get_all_modules():
            if m.name in ["CNAME"]:
                selected_modules.append(m)
        return selected_modules


class TestBaddns_cname_nxdomain(BaseTestBaddns):
    async def setup_after_prep(self, module_test):
        from bbot.modules import baddns as baddns_module
        from baddns.lib.whoismanager import WhoisManager

        await module_test.mock_dns(
            {"bad.dns": {"CNAME": ["baddns.azurewebsites.net."]}, "_NXDOMAIN": ["baddns.azurewebsites.net"]}
        )
        module_test.monkeypatch.setattr(baddns_module.baddns, "select_modules", self.select_modules)
        module_test.monkeypatch.setattr(WhoisManager, "dispatchWHOIS", self.dispatchWHOIS)

    def check(self, module_test, events):
        assert any(e.data == "baddns.azurewebsites.net" for e in events), "CNAME detection failed"
        assert any(e.type == "FINDING" for e in events), "Failed to emit FINDING"
        assert any("baddns-cname" in e.tags for e in events), "Failed to add baddns tag"


class TestBaddns_cname_signature(BaseTestBaddns):
    targets = [f"bad.dns:{HTTPSERVER_PORT}"]
    modules_overrides = ["baddns", "speculate"]

    async def setup_after_prep(self, module_test):
        from bbot.modules import baddns as baddns_module
        from baddns.base import BadDNS_base
        from baddns.lib.whoismanager import WhoisManager

        def set_target(self, target):
            return HTTPSERVER_HOSTPORT

        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "<h1>Oops! We couldn&#8217;t find that page.</h1>", "status": 200}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        await module_test.mock_dns(
            {"bad.dns": {"CNAME": ["baddns.bigcartel.com."]}, "baddns.bigcartel.com": {"A": ["127.0.0.1"]}}
        )
        module_test.monkeypatch.setattr(baddns_module.baddns, "select_modules", self.select_modules)
        module_test.monkeypatch.setattr(BadDNS_base, "set_target", set_target)
        module_test.monkeypatch.setattr(WhoisManager, "dispatchWHOIS", self.dispatchWHOIS)

    def check(self, module_test, events):
        assert any(e for e in events)
        assert any(e.type == "FINDING" and "bigcartel.com" in e.data["description"] for e in events), (
            "Failed to emit FINDING"
        )
        assert any("baddns-cname" in e.tags for e in events), "Failed to add baddns tag"
