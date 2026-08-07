"""
Dependency handling for the pseudotools.

Several tools shell out to binaries BBOT installs rather than ships: masscan,
fingerprintx, trufflehog, jadx, gowitness and others. In an image that already
has them (`bbot-docker-full`, or any environment where BBOT has run before)
there is nothing to do, and this module does nothing.

So the server never installs anything on its own. It reports what is missing at
startup and points at `bbot-mcp --install-deps`, which is an explicit operator
action. `DepsInstaller.install()` is itself idempotent -- modules with no
dependencies short-circuit and cached successes are skipped -- so running it
when everything is already present is a no-op rather than a reinstall.
"""

import logging
import pathlib
import shutil

log = logging.getLogger("bbot.mcp.deps")


def required_modules(registry):
    """Every BBOT module the pseudotools can enable, across all of them."""
    modules = set()
    for entry in registry:
        try:
            modules.update(entry.facts.modules)
        except Exception as e:
            log.warning('could not resolve modules for "%s": %s', entry.name, e)
    return sorted(modules)


def _binaries(preloaded):
    """Binaries a module needs on PATH, from its apt and common deps."""
    deps = preloaded.get("deps") or {}
    return sorted({str(p) for key in ("apt", "common") for p in (deps.get(key) or [])})


def _pip_satisfied(pip_deps):
    """Reuse BBOT's own pip check rather than reimplementing specifier matching.

    `DepsInstaller._pip_deps_satisfied` never touches `self`, so it can be called
    unbound. Better a slightly awkward call than a second, subtly different
    implementation of "is this requirement installed".
    """
    from bbot.core.helpers.depsinstaller.installer import DepsInstaller

    try:
        return DepsInstaller._pip_deps_satisfied(None, pip_deps)
    except Exception as e:  # never let a status check break anything
        log.debug("pip dependency check failed: %s", e)
        return True, ""


def _tools_dir():
    """Where BBOT drops the binaries it downloads itself."""
    from bbot.core import CORE

    return pathlib.Path(CORE.home) / "tools"


def root_available():
    """Whether BBOT can get root without asking a human.

    This matters far more here than on the CLI. `DepsInstaller.ensure_root()`
    falls back to `getpass.getpass()`, and with no TTY `getpass` reads
    `sys.stdin` -- which in a stdio MCP server is the JSON-RPC channel itself.
    A module needing root would therefore block forever waiting for a password
    while consuming the protocol stream, taking the whole server down rather
    than failing one scan.
    """
    import os

    if os.environ.get("BBOT_SUDO_PASS"):
        return True
    if os.geteuid() == 0:
        return True
    try:
        from bbot.core.helpers.misc import can_sudo_without_password

        return bool(can_sudo_without_password())
    except Exception as e:
        log.debug("could not determine sudo availability: %s", e)
        return False


def _escalates_at_runtime(path):
    """Whether a module asks for root while scanning, rather than while installing.

    The preloaded `sudo` flag means "installing this needs root", which is a
    different question: `dnsbrute` carries it but never escalates once massdns is
    present, while `portscan` calls `ensure_root()` from `setup()` on every scan.
    Warning on the flag alone cries wolf on tools that work fine, so read what the
    module actually does.
    """
    try:
        source = pathlib.Path(path).read_text()
    except OSError:
        return False
    return "ensure_root(" in source or "sudo=True" in source


def modules_needing_root(entry):
    """Modules in one pseudotool that will try to escalate during a scan."""
    from bbot.core.modules import MODULE_LOADER

    preloaded = MODULE_LOADER.preloaded()
    return sorted(
        m
        for m in entry.facts.modules
        if (preloaded.get(m) or {}).get("sudo") and _escalates_at_runtime((preloaded.get(m) or {}).get("path", ""))
    )


def report(registry):
    """Dependency status for the modules the pseudotools use.

    Returns `(installable, privileged)`, two dicts of `{module: [reasons]}`.

    They are kept apart because only one of them is an install problem.
    `installable` is what `--install-deps` fixes. `privileged` is a module whose
    dependencies are already present but which escalates while scanning, so
    there is nothing to install and running the installer would report success
    while changing nothing -- which reads as the tool contradicting itself.
    """
    from bbot.core.modules import MODULE_LOADER

    preloaded = MODULE_LOADER.preloaded()
    tools = _tools_dir()
    have_root = root_available()
    installable = {}
    privileged = {}
    for name in required_modules(registry):
        module = preloaded.get(name)
        if not module:
            continue
        deps = module.get("deps") or {}
        reasons = []

        satisfied, why = _pip_satisfied(deps.get("pip") or [])
        if not satisfied:
            reasons.append(why)

        missing_binaries = [
            binary
            for binary in _binaries(module)
            # BBOT installs some of these itself rather than through apt
            if not shutil.which(binary) and not (tools / binary).exists()
        ]
        if missing_binaries:
            reasons.append(f"missing binary: {', '.join(missing_binaries)}")

        # an ansible dep downloads a binary, conventionally named after the module
        if deps.get("ansible") and not (tools / name).exists() and not shutil.which(name):
            reasons.append("binary not downloaded yet")

        if reasons:
            if module.get("sudo"):
                reasons.append("installing it needs root")
            installable[name] = reasons
        elif not have_root and _escalates_at_runtime(module.get("path", "")):
            # nothing to install: it is installed, and it wants root to run
            privileged[name] = ["escalates while scanning; no passwordless sudo or BBOT_SUDO_PASS available"]
    return installable, privileged


async def install(registry):
    """Install dependencies for exactly the modules the pseudotools use.

    Not every BBOT module -- `bbot --install-all-deps` already does that, and it
    is a much larger job than this layer needs.
    """
    from bbot.scanner import Preset, Scanner

    modules = required_modules(registry)
    if not modules:
        log.warning("no pseudotool modules to install dependencies for")
        return True

    # A throwaway scan, solely so Preset.bake(scan) resolves the "#{BBOT_TOOLS}"
    # style placeholders in module configs before ansible runs. Same reason the
    # CLI does it for --install-all-deps.
    preset = Preset(modules=modules, _log=False)
    preset.validate()
    scan = Scanner(preset=preset.bake())

    log.info("installing dependencies for %d modules used by the pseudotools", len(modules))
    succeeded, failed = await scan.helpers.depsinstaller.install(*modules)
    if succeeded:
        log.info("dependencies satisfied for %d modules", len(succeeded))
    if failed:
        log.warning("failed to install dependencies for: %s", ", ".join(sorted(failed)))
        return False

    # Installing cannot fix a module that escalates while scanning, so say so
    # here too. Otherwise this exits with a clean success while a tool remains
    # broken, and the operator has to have read --check-deps to know.
    _, privileged = report(registry)
    if privileged:
        log.warning(
            "still unusable without root: %s. Nothing to install -- set BBOT_SUDO_PASS, "
            "configure passwordless sudo, or run the server as root.",
            ", ".join(sorted(privileged)),
        )
    return True


def api_key_status(registry):
    """Which pseudotool modules take an API key, and whether one is configured.

    Operator-facing only. The MCP tools deliberately never look at local config
    when describing themselves -- that would leak which keys an operator holds
    into agent-visible output -- but a CLI run by that operator is a different
    audience.

    Returns `(configured, missing)`, each `{module: [dotted option paths]}`.
    Values are never read or printed, only presence.
    """
    from bbot.core import CORE
    from bbot.core.modules import MODULE_LOADER

    preloaded = MODULE_LOADER.preloaded()
    configured, missing = {}, {}
    for name in required_modules(registry):
        module = preloaded.get(name) or {}
        # `options_mandatory` misses modules whose template calls
        # require_api_key() without declaring it -- github_org is one -- so fall
        # back to any option that looks like a credential.
        options = set(module.get("options_mandatory") or [])
        options |= {o for o in (module.get("config") or {}) if "api_key" in o or "api_id" in o}
        if not options:
            continue
        set_here, unset_here = [], []
        current = (CORE.config.get("modules") or {}).get(name) or {}
        for option in sorted(options):
            (set_here if current.get(option) else unset_here).append(f"modules.{name}.{option}")
        if set_here:
            configured[name] = set_here
        if unset_here:
            missing[name] = unset_here
    return configured, missing


def secrets_path():
    from bbot.core import CORE

    return CORE.files_config.secrets_filename


# Prefix for per-option config injection, e.g.
# BBOT_MODULES_SHODAN_DNS_API_KEY -> modules.shodan_dns.api_key
ENV_PREFIX = "BBOT_MODULES_"


def config_from_env(env=None):
    """Read module config out of the environment.

    BBOT itself has no env-var config mechanism: keys live in
    `~/.config/bbot/secrets.yml`. That is fine on a workstation and unworkable
    in a container, where the file is inside an ephemeral image and the MCP
    client is what invokes `docker run`. MCP clients do have a standard `env`
    block for a server, so this bridges the two.

    Module names contain underscores, so `BBOT_MODULES_SHODAN_DNS_API_KEY` is
    ambiguous by string-splitting alone. It is resolved against the real module
    list, longest name first, so `shodan_dns` wins over any shorter prefix.

    Returns a nested dict suitable for `CORE.merge_custom`.
    """
    import os

    from bbot.core.modules import MODULE_LOADER

    env = os.environ if env is None else env
    known = sorted(MODULE_LOADER.preloaded(), key=len, reverse=True)
    config = {}
    for key, value in env.items():
        if not key.startswith(ENV_PREFIX) or not value:
            continue
        remainder = key[len(ENV_PREFIX) :].lower()
        for module in known:
            if remainder.startswith(module + "_"):
                option = remainder[len(module) + 1 :]
                if option:
                    config.setdefault("modules", {}).setdefault(module, {})[option] = value
                break
        else:
            log.warning('ignoring %s: no module matches "%s"', key, remainder)
    return config


def apply_env_config():
    """Merge any env-supplied module config into BBOT's config. Returns what it set."""
    from bbot.core import CORE

    config = config_from_env()
    if config:
        CORE.merge_custom(config)
        return {m: sorted(opts) for m, opts in config["modules"].items()}
    return {}
