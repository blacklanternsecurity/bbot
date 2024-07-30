import os
import sys
import stat
import json
import shutil
import getpass
import logging
from time import sleep
from pathlib import Path
from threading import Lock
from itertools import chain
from contextlib import suppress
from ansible_runner.interface import run
from subprocess import CalledProcessError

from ..misc import can_sudo_without_password, os_platform

log = logging.getLogger("bbot.core.helpers.depsinstaller")


class DepsInstaller:
    def __init__(self, parent_helper):
        self.parent_helper = parent_helper
        self.preset = self.parent_helper.preset
        self.core = self.preset.core

        # respect BBOT's http timeout
        self.web_config = self.parent_helper.config.get("web", {})
        http_timeout = self.web_config.get("http_timeout", 30)
        os.environ["ANSIBLE_TIMEOUT"] = str(http_timeout)

        self.askpass_filename = "sudo_askpass.py"
        self._installed_sudo_askpass = False
        self._sudo_password = os.environ.get("BBOT_SUDO_PASS", None)
        if self._sudo_password is None:
            if self.core.bbot_sudo_pass is not None:
                self._sudo_password = self.core.bbot_sudo_pass
            elif can_sudo_without_password():
                self._sudo_password = ""
        self.data_dir = self.parent_helper.cache_dir / "depsinstaller"
        self.parent_helper.mkdir(self.data_dir)
        self.setup_status_cache = self.data_dir / "setup_status.json"
        self.command_status = self.data_dir / "command_status"
        self.parent_helper.mkdir(self.command_status)
        self.setup_status = self.read_setup_status()

        self.deps_behavior = self.parent_helper.config.get("deps_behavior", "abort_on_failure").lower()
        self.ansible_debug = self.core.logger.log_level <= logging.DEBUG
        self.venv = ""
        if sys.prefix != sys.base_prefix:
            self.venv = sys.prefix

        self.ensure_root_lock = Lock()

    async def install(self, *modules):
        self.install_core_deps()
        succeeded = []
        failed = []
        try:
            notified = False
            for m in modules:
                # assume success if we're ignoring dependencies
                if self.deps_behavior == "disable":
                    succeeded.append(m)
                    continue
                # abort if module name is unknown
                if m not in self.all_modules_preloaded:
                    log.verbose(f'Module "{m}" not found')
                    failed.append(m)
                    continue
                preloaded = self.all_modules_preloaded[m]
                log.debug(f"Installing {m} - Preloaded Deps {preloaded['deps']}")
                # make a hash of the dependencies and check if it's already been handled
                # take into consideration whether the venv or bbot home directory changes
                module_hash = self.parent_helper.sha1(
                    json.dumps(preloaded["deps"], sort_keys=True)
                    + self.venv
                    + str(self.parent_helper.bbot_home)
                    + os.uname()[1]
                ).hexdigest()
                success = self.setup_status.get(module_hash, None)
                dependencies = list(chain(*preloaded["deps"].values()))
                if len(dependencies) <= 0:
                    log.debug(f'No dependency work to do for module "{m}"')
                    succeeded.append(m)
                    continue
                else:
                    if (
                        success is None
                        or (success is False and self.deps_behavior == "retry_failed")
                        or self.deps_behavior == "force_install"
                    ):
                        if not notified:
                            log.hugeinfo(f"Installing module dependencies. Please be patient, this may take a while.")
                            notified = True
                        log.verbose(f'Installing dependencies for module "{m}"')
                        # get sudo access if we need it
                        if preloaded.get("sudo", False) == True:
                            self.ensure_root(f'Module "{m}" needs root privileges to install its dependencies.')
                        success = await self.install_module(m)
                        self.setup_status[module_hash] = success
                        if success or self.deps_behavior == "ignore_failed":
                            log.debug(f'Setup succeeded for module "{m}"')
                            succeeded.append(m)
                        else:
                            log.warning(f'Setup failed for module "{m}"')
                            failed.append(m)
                    else:
                        if success or self.deps_behavior == "ignore_failed":
                            log.debug(
                                f'Skipping dependency install for module "{m}" because it\'s already done (--force-deps to re-run)'
                            )
                            succeeded.append(m)
                        else:
                            log.warning(
                                f'Skipping dependency install for module "{m}" because it failed previously (--retry-deps to retry or --ignore-failed-deps to ignore)'
                            )
                            failed.append(m)

        finally:
            self.write_setup_status()

        succeeded.sort()
        failed.sort()
        return succeeded, failed

    async def install_module(self, module):
        success = True
        preloaded = self.all_modules_preloaded[module]

        # ansible tasks
        ansible_tasks = preloaded["deps"]["ansible"]
        if ansible_tasks:
            success &= self.tasks(module, ansible_tasks)

        # apt
        deps_apt = preloaded["deps"]["apt"]
        if deps_apt:
            self.apt_install(deps_apt)

        # shell
        deps_shell = preloaded["deps"]["shell"]
        if deps_shell:
            success &= self.shell(module, deps_shell)

        # pip
        deps_pip = preloaded["deps"]["pip"]
        deps_pip_constraints = preloaded["deps"]["pip_constraints"]
        if deps_pip:
            success &= await self.pip_install(deps_pip, constraints=deps_pip_constraints)

        # shared/common
        deps_common = preloaded["deps"]["common"]
        if deps_common:
            for dep_common in deps_common:
                if self.setup_status.get(dep_common, False) == True:
                    log.debug(
                        f'Skipping installation of dependency "{dep_common}" for module "{module}" since it is already installed'
                    )
                    continue
                ansible_tasks = self.preset.module_loader._shared_deps[dep_common]
                result = self.tasks(module, ansible_tasks)
                self.setup_status[dep_common] = result
                success &= result

        return success

    async def pip_install(self, packages, constraints=None):
        packages_str = ",".join(packages)
        log.info(f"Installing the following pip packages: {packages_str}")

        command = [sys.executable, "-m", "pip", "install", "--upgrade"] + packages

        if constraints:
            constraints_tempfile = self.parent_helper.tempfile(constraints, pipe=False)
            command.append("--constraint")
            command.append(constraints_tempfile)

        process = None
        try:
            process = await self.parent_helper.run(command, check=True)
            message = f'Successfully installed pip packages "{packages_str}"'
            output = process.stdout
            if output is not None:
                message = output.splitlines()[-1]
            log.info(message)
            return True
        except CalledProcessError as err:
            log.warning(f"Failed to install pip packages {packages_str} (return code {err.returncode}): {err.stderr}")
        return False

    def apt_install(self, packages):
        """
        Install packages with the OS's default package manager (apt, pacman, dnf, etc.)
        """
        packages_str = ",".join(packages)
        log.info(f"Installing the following OS packages: {packages_str}")
        args = {"name": packages_str, "state": "present"}  # , "update_cache": True, "cache_valid_time": 86400}
        kwargs = {}
        # don't sudo brew
        if os_platform() != "darwin":
            kwargs = {
                "ansible_args": {
                    "ansible_become": True,
                    "ansible_become_method": "sudo",
                }
            }
        success, err = self.ansible_run(module="package", args=args, **kwargs)
        if success:
            log.info(f'Successfully installed OS packages "{packages_str}"')
        else:
            log.warning(
                f"Failed to install OS packages ({err}). Recommend installing the following packages manually:"
            )
            for p in packages:
                log.warning(f" - {p}")
        return success

    def shell(self, module, commands):
        tasks = []
        for i, command in enumerate(commands):
            command_hash = self.parent_helper.sha1(f"{module}_{i}_{command}").hexdigest()
            command_status_file = self.command_status / command_hash
            if type(command) == str:
                command = {"cmd": command}
            command["cmd"] += f" && touch {command_status_file}"
            tasks.append(
                {
                    "name": f"{module}.deps_shell step {i+1}",
                    "ansible.builtin.shell": command,
                    "args": {"executable": "/bin/bash", "creates": str(command_status_file)},
                }
            )
        success, err = self.ansible_run(tasks=tasks)
        if success:
            log.info(f"Successfully ran {len(commands):,} shell commands")
        else:
            log.warning(f"Failed to run shell dependencies")
        return success

    def tasks(self, module, tasks):
        log.info(f"Running {len(tasks):,} Ansible tasks for {module}")
        success, err = self.ansible_run(tasks=tasks)
        if success:
            log.info(f"Successfully ran {len(tasks):,} Ansible tasks for {module}")
        else:
            log.warning(f"Failed to run Ansible tasks for {module}")
        return success

    def ansible_run(self, tasks=None, module=None, args=None, ansible_args=None):
        _ansible_args = {"ansible_connection": "local"}
        if ansible_args is not None:
            _ansible_args.update(ansible_args)
        module_args = None
        if args:
            module_args = " ".join([f'{k}="{v}"' for k, v in args.items()])
        log.debug(f"ansible_run(module={module}, args={args}, ansible_args={ansible_args})")
        playbook = None
        if tasks:
            for task in tasks:
                if "package" in task:
                    # special case for macos
                    if os_platform() == "darwin":
                        # don't sudo brew
                        task["become"] = False
                        # brew doesn't support update_cache
                        task["package"].pop("update_cache", "")
            playbook = {"hosts": "all", "tasks": tasks}
            log.debug(json.dumps(playbook, indent=2))
        if self._sudo_password is not None:
            _ansible_args["ansible_become_password"] = self._sudo_password
        playbook_hash = self.parent_helper.sha1(str(playbook)).hexdigest()
        data_dir = self.data_dir / (module if module else f"playbook_{playbook_hash}")
        shutil.rmtree(data_dir, ignore_errors=True)
        self.parent_helper.mkdir(data_dir)

        res = run(
            playbook=playbook,
            private_data_dir=str(data_dir),
            host_pattern="localhost",
            inventory={
                "all": {"hosts": {"localhost": _ansible_args}},
            },
            module=module,
            module_args=module_args,
            quiet=not self.ansible_debug,
            verbosity=(3 if self.ansible_debug else 0),
            cancel_callback=lambda: None,
        )

        log.debug(f"Ansible status: {res.status}")
        log.debug(f"Ansible return code: {res.rc}")
        success = res.status == "successful"
        err = ""
        for e in res.events:
            if self.ansible_debug and not success:
                log.debug(json.dumps(e, indent=4))
            if e["event"] == "runner_on_failed":
                err = e["event_data"]["res"]["msg"]
                break
        return success, err

    def read_setup_status(self):
        setup_status = dict()
        if self.setup_status_cache.is_file():
            with open(self.setup_status_cache) as f:
                with suppress(Exception):
                    setup_status = json.load(f)
        return setup_status

    def write_setup_status(self):
        with open(self.setup_status_cache, "w") as f:
            json.dump(self.setup_status, f)

    def ensure_root(self, message=""):
        self._install_sudo_askpass()
        with self.ensure_root_lock:
            if os.geteuid() != 0 and self._sudo_password is None:
                if message:
                    log.warning(message)
                while not self._sudo_password:
                    # sleep for a split second to flush previous log messages
                    sleep(0.1)
                    password = getpass.getpass(prompt="[USER] Please enter sudo password: ")
                    if self.parent_helper.verify_sudo_password(password):
                        log.success("Authentication successful")
                        self._sudo_password = password
                        self.core.bbot_sudo_pass = password
                    else:
                        log.warning("Incorrect password")

    def install_core_deps(self):
        to_install = set()
        self._install_sudo_askpass()
        # ensure tldextract data is cached
        self.parent_helper.tldextract("evilcorp.co.uk")
        # command: package_name
        core_deps = {"unzip": "unzip", "curl": "curl"}
        for command, package_name in core_deps.items():
            if not self.parent_helper.which(command):
                to_install.add(package_name)
        if to_install:
            self.ensure_root()
            self.apt_install(list(to_install))

    def _install_sudo_askpass(self):
        if not self._installed_sudo_askpass:
            self._installed_sudo_askpass = True
            # install custom askpass script
            askpass_src = Path(__file__).resolve().parent / self.askpass_filename
            askpass_dst = self.parent_helper.tools_dir / self.askpass_filename
            shutil.copy(askpass_src, askpass_dst)
            askpass_dst.chmod(askpass_dst.stat().st_mode | stat.S_IEXEC)

    @property
    def all_modules_preloaded(self):
        return self.preset.module_loader.preloaded()
