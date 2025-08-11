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
from secrets import token_bytes
from ansible_runner.interface import run
from subprocess import CalledProcessError

from ..misc import can_sudo_without_password, os_platform, rm_at_exit, get_python_constraints

log = logging.getLogger("bbot.core.helpers.depsinstaller")


class DepsInstaller:
    CORE_DEPS = {
        # core BBOT dependencies in the format of binary: package_name
        # each one will only be installed if the binary is not found
        "unzip": "unzip",
        "zipinfo": "unzip",
        "curl": "curl",
        "git": "git",
        "make": "make",
        "gcc": "gcc",
        "bash": "bash",
        "which": "which",
        "tar": "tar",
        "xz": [
            {
                "name": "Install xz-utils (Debian)",
                "package": {"name": ["xz-utils"], "state": "present"},
                "become": True,
                "when": "ansible_facts['os_family'] == 'Debian'",
            },
            {
                "name": "Install xz (Non-Debian)",
                "package": {"name": ["xz"], "state": "present"},
                "become": True,
                "when": "ansible_facts['os_family'] != 'Debian'",
            },
        ],
        # debian why are you like this
        "7z": [
            {
                "name": "Install 7zip (Debian)",
                "package": {"name": ["p7zip-full"], "state": "present"},
                "become": True,
                "when": "ansible_facts['os_family'] == 'Debian'",
            },
            {
                "name": "Install 7zip (Non-Debian)",
                "package": {"name": ["p7zip"], "state": "present"},
                "become": True,
                "when": "ansible_facts['os_family'] != 'Debian'",
            },
            {
                "name": "Install p7zip-plugins (Fedora)",
                "package": {"name": ["p7zip-plugins"], "state": "present"},
                "become": True,
                "when": "ansible_facts['distribution'] == 'Fedora'",
            },
        ],
        # to compile just about any tool, we need the openssl dev headers
        "openssl": [
            {
                "name": "Install OpenSSL library and development headers (Debian/Ubuntu)",
                "package": {"name": ["libssl-dev", "openssl"], "state": "present"},
                "become": True,
                "when": "ansible_facts['os_family'] == 'Debian'",
                "ignore_errors": True,
            },
            {
                "name": "Install OpenSSL library and development headers (RedHat/CentOS/Fedora)",
                "package": {"name": ["openssl", "openssl-devel"], "state": "present"},
                "become": True,
                "when": "ansible_facts['os_family'] == 'RedHat' or ansible_facts['os_family'] == 'Suse' ",
                "ignore_errors": True,
            },
            {
                "name": "Install OpenSSL library and development headers (Arch)",
                "package": {"name": ["openssl"], "state": "present"},
                "become": True,
                "when": "ansible_facts['os_family'] == 'Archlinux'",
                "ignore_errors": True,
            },
            {
                "name": "Install OpenSSL library and development headers (Alpine)",
                "package": {"name": ["openssl", "openssl-dev"], "state": "present"},
                "become": True,
                "when": "ansible_facts['os_family'] == 'Alpine'",
                "ignore_errors": True,
            },
            {
                "name": "Install OpenSSL library and development headers (FreeBSD)",
                "package": {"name": ["openssl"], "state": "present"},
                "become": True,
                "when": "ansible_facts['os_family'] == 'FreeBSD'",
                "ignore_errors": True,
            },
        ],
    }

    def __init__(self, parent_helper):
        self.parent_helper = parent_helper
        self.preset = self.parent_helper.preset
        self.core = self.preset.core

        self.os_platform = os_platform()

        # respect BBOT's http timeout
        self.web_config = self.parent_helper.config.get("web", {})
        http_timeout = self.web_config.get("http_timeout", 30)
        os.environ["ANSIBLE_TIMEOUT"] = str(http_timeout)

        # cache encrypted sudo pass
        self.askpass_filename = "sudo_askpass.py"
        self._sudo_password = None
        self._sudo_cache_setup = False
        self._setup_sudo_cache()
        self._installed_sudo_askpass = False

        self.data_dir = self.parent_helper.cache_dir / "depsinstaller"
        self.parent_helper.mkdir(self.data_dir)
        self.setup_status_cache = self.data_dir / "setup_status.json"
        self.command_status = self.data_dir / "command_status"
        self.parent_helper.mkdir(self.command_status)
        self.setup_status = self.read_setup_status()

        # make sure we're using a minimal git config
        self.minimal_git_config = self.data_dir / "minimal_git.config"
        self.minimal_git_config.touch()
        os.environ["GIT_CONFIG_GLOBAL"] = str(self.minimal_git_config)

        self.deps_config = self.parent_helper.config.get("deps", {})
        self.deps_behavior = self.deps_config.get("behavior", "abort_on_failure").lower()
        self.ansible_debug = self.core.logger.log_level <= logging.DEBUG
        self.venv = ""
        if sys.prefix != sys.base_prefix:
            self.venv = sys.prefix

        self.ensure_root_lock = Lock()

    async def install(self, *modules):
        await self.install_core_deps()
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
                            log.hugeinfo("Installing module dependencies. Please be patient, this may take a while.")
                            notified = True
                        log.verbose(f'Installing dependencies for module "{m}"')
                        # get sudo access if we need it
                        if preloaded.get("sudo", False) is True:
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
                if self.setup_status.get(dep_common, False) is True and self.deps_behavior != "force_install":
                    log.debug(
                        f'Skipping installation of dependency "{dep_common}" for module "{module}" since it is already installed'
                    )
                    continue
                ansible_tasks = self.preset.module_loader._shared_deps[dep_common]
                result = self.tasks(module, ansible_tasks)
                self.setup_status[dep_common] = result
                success &= result

        # ansible tasks
        ansible_tasks = preloaded["deps"]["ansible"]
        if ansible_tasks:
            success &= self.tasks(module, ansible_tasks)

        return success

    async def pip_install(self, packages, constraints=None):
        packages_str = ",".join(packages)
        log.info(f"Installing the following pip packages: {packages_str}")

        command = [sys.executable, "-m", "pip", "install", "--upgrade"] + packages

        # if no custom constraints are provided, use the constraints of the currently installed version of bbot
        if constraints is not None:
            constraints = get_python_constraints()

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
        args, kwargs = self._make_apt_ansible_args(packages)
        success, err = self.ansible_run(module="package", args=args, **kwargs)
        if success:
            log.info(f'Successfully installed OS packages "{",".join(sorted(packages))}"')
        else:
            log.warning(
                f"Failed to install OS packages ({err}). Recommend installing the following packages manually:"
            )
            for p in packages:
                log.warning(f" - {p}")
        return success

    def _make_apt_ansible_args(self, packages):
        packages_str = ",".join(sorted(packages))
        log.info(f"Installing the following OS packages: {packages_str}")
        args = {"name": packages_str, "state": "present"}  # , "update_cache": True, "cache_valid_time": 86400}
        kwargs = {}
        # don't sudo brew
        if self.os_platform != "darwin":
            kwargs = {
                "ansible_args": {
                    "ansible_become": True,
                    "ansible_become_method": "sudo",
                }
            }
        return args, kwargs

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
                    "name": f"{module}.deps_shell step {i + 1}",
                    "ansible.builtin.shell": command,
                    "args": {"executable": "/bin/bash", "creates": str(command_status_file)},
                }
            )
        success, err = self.ansible_run(tasks=tasks)
        if success:
            log.info(f"Successfully ran {len(commands):,} shell commands")
        else:
            log.warning("Failed to run shell dependencies")
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
        _ansible_args = {"ansible_connection": "local", "ansible_python_interpreter": sys.executable}
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
                    if self.os_platform == "darwin":
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
            quiet=True,
            verbosity=0,
            cancel_callback=lambda: None,
        )

        log.debug(f"Ansible status: {res.status}")
        log.debug(f"Ansible return code: {res.rc}")
        success = res.status == "successful"
        err = ""
        for e in res.events:
            if self.ansible_debug and not success:
                log.debug(json.dumps(e, indent=2))
            if e["event"] == "runner_on_failed":
                err = e["event_data"]["res"]["msg"]
                break
        return success, err

    def read_setup_status(self):
        setup_status = {}
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
        # skip if we've already done this
        if self._sudo_password is not None:
            return
        with self.ensure_root_lock:
            # first check if the environment variable is set
            _sudo_password = os.environ.get("BBOT_SUDO_PASS", None)
            if _sudo_password is not None or os.geteuid() == 0 or can_sudo_without_password():
                # if we're already root or we can sudo without a password, there's no need to prompt
                return

            if message:
                log.warning(message)
            while not self._sudo_password:
                # sleep for a split second to flush previous log messages
                sleep(0.1)
                _sudo_password = getpass.getpass(prompt="[USER] Please enter sudo password: ")
                if self.parent_helper.verify_sudo_password(_sudo_password):
                    log.success("Authentication successful")
                    self._sudo_password = _sudo_password
                else:
                    log.warning("Incorrect password")

    async def install_core_deps(self):
        to_install = set()
        to_install_friendly = set()
        playbook = []
        self._install_sudo_askpass()
        # ensure tldextract data is cached
        self.parent_helper.tldextract("evilcorp.co.uk")
        # install any missing commands
        for command, package_name_or_playbook in self.CORE_DEPS.items():
            if not self.parent_helper.which(command):
                to_install_friendly.add(command)
                if isinstance(package_name_or_playbook, str):
                    to_install.add(package_name_or_playbook)
                else:
                    playbook.extend(package_name_or_playbook)
        # install ansible community.general collection
        if not self.setup_status.get("ansible:community.general", False):
            log.info("Installing Ansible Community General Collection")
            try:
                command = ["ansible-galaxy", "collection", "install", "community.general"]
                await self.parent_helper.run(command, check=True)
                self.setup_status["ansible:community.general"] = True
                log.info("Successfully installed Ansible Community General Collection")
            except CalledProcessError as err:
                log.warning(
                    f"Failed to install Ansible Community.General Collection (return code {err.returncode}): {err.stderr}"
                )
        # construct ansible playbook
        if to_install:
            playbook.append(
                {
                    "name": "Install Core BBOT Dependencies",
                    "package": {"name": list(to_install), "state": "present"},
                    "become": True,
                }
            )
        # run playbook
        if playbook:
            log.info(f"Installing core BBOT dependencies: {','.join(sorted(to_install_friendly))}")
            self.ensure_root()
            self.ansible_run(tasks=playbook)

    def _setup_sudo_cache(self):
        if not self._sudo_cache_setup:
            self._sudo_cache_setup = True
            # write temporary encryption key, to be deleted upon scan completion
            self._sudo_temp_keyfile = self.parent_helper.temp_filename()
            # remove it at exit
            rm_at_exit(self._sudo_temp_keyfile)
            # generate random 32-byte key
            random_key = token_bytes(32)
            # write key to file and set secure permissions
            self._sudo_temp_keyfile.write_bytes(random_key)
            self._sudo_temp_keyfile.chmod(0o600)
            # export path to environment variable, for use in askpass script
            os.environ["BBOT_SUDO_KEYFILE"] = str(self._sudo_temp_keyfile.resolve())

    @property
    def encrypted_sudo_pw(self):
        if self._sudo_password is None:
            return ""
        return self._encrypt_sudo_pw(self._sudo_password)

    def _encrypt_sudo_pw(self, pw):
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad

        key = self._sudo_temp_keyfile.read_bytes()
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(pw.encode(), AES.block_size))
        iv = cipher.iv.hex()
        ct = ct_bytes.hex()
        return f"{iv}:{ct}"

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
