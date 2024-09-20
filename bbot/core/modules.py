import re
import ast
import sys
import atexit
import pickle
import logging
import importlib
import omegaconf
import traceback
from copy import copy
from pathlib import Path
from omegaconf import OmegaConf
from contextlib import suppress

from bbot.core import CORE
from bbot.errors import BBOTError
from bbot.logger import log_to_stderr

from .flags import flag_descriptions
from .shared_deps import SHARED_DEPS
from .helpers.misc import (
    list_files,
    sha1,
    search_dict_by_key,
    search_format_dict,
    make_table,
    os_platform,
    mkdir,
)


log = logging.getLogger("bbot.module_loader")

bbot_code_dir = Path(__file__).parent.parent


class ModuleLoader:
    """
    Main class responsible for preloading BBOT modules.

    This class is in charge of preloading modules to determine their dependencies.
    Once dependencies are identified, they are installed before the actual module is imported.
    This ensures that all requisite libraries and components are available for the module to function correctly.
    """

    default_module_dir = bbot_code_dir / "modules"

    module_dir_regex = re.compile(r"^[a-z][a-z0-9_]*$")

    # if a module consumes these event types, automatically assume these dependencies
    default_module_deps = {"HTTP_RESPONSE": "httpx", "URL": "httpx", "SOCIAL": "social"}

    def __init__(self):
        self.core = CORE

        self._shared_deps = dict(SHARED_DEPS)

        self.__preloaded = {}
        self._modules = {}
        self._configs = {}
        self.flag_choices = set()
        self.all_module_choices = set()
        self.scan_module_choices = set()
        self.output_module_choices = set()
        self.internal_module_choices = set()

        self._preload_cache = None

        self._module_dirs = set()
        self._module_dirs_preloaded = set()
        self.add_module_dir(self.default_module_dir)

        # save preload cache before exiting
        atexit.register(self.save_preload_cache)

    def copy(self):
        module_loader_copy = copy(self)
        module_loader_copy.__preloaded = dict(self.__preloaded)
        return module_loader_copy

    @property
    def preload_cache_file(self):
        return self.core.cache_dir / "module_preload_cache"

    @property
    def module_dirs(self):
        return self._module_dirs

    def add_module_dir(self, module_dir):
        module_dir = Path(module_dir).resolve()
        if module_dir in self._module_dirs:
            log.debug(f'Already added custom module dir "{module_dir}"')
            return
        if not module_dir.is_dir():
            log.warning(f'Failed to add custom module dir "{module_dir}", please make sure it exists')
            return
        new_module_dirs = set()
        for _module_dir in self.get_recursive_dirs(module_dir):
            _module_dir = Path(_module_dir).resolve()
            if _module_dir not in self._module_dirs:
                self._module_dirs.add(_module_dir)
                new_module_dirs.add(_module_dir)
        self.preload(module_dirs=new_module_dirs)

    def file_filter(self, file):
        file = file.resolve()
        if "templates" in file.parts:
            return False
        return file.suffix.lower() == ".py" and file.stem not in ["base", "__init__"]

    def preload(self, module_dirs=None):
        """Preloads all BBOT modules.

        This function recursively iterates through each file in the module directories
        and preloads each BBOT module to gather its meta-information and dependencies.

        Args:
            module_dir (str or Path): Directory containing BBOT modules to be preloaded.

        Returns:
            dict: A dictionary where keys are the names of the preloaded modules and
            values are their respective preloaded data.

        Examples:
            >>> preload("/path/to/bbot_modules/")
            {
                "module1": {...},
                "module2": {...},
                ...
            }
        """
        new_modules = False
        if module_dirs is None:
            module_dirs = self.module_dirs

        for module_dir in module_dirs:
            if module_dir in self._module_dirs_preloaded:
                log.debug(f"Already preloaded modules from {module_dir}")
                continue

            log.debug(f"Preloading modules from {module_dir}")
            new_modules = True
            for module_file in list_files(module_dir, filter=self.file_filter):
                module_name = module_file.stem
                module_file = module_file.resolve()

                # try to load from cache
                module_cache_key = (str(module_file), tuple(module_file.stat()))
                preloaded = self.preload_cache.get(module_name, {})
                cache_key = preloaded.get("cache_key", ())
                if preloaded and module_cache_key == cache_key:
                    log.debug(f"Preloading {module_name} from cache")
                else:
                    log.debug(f"Preloading {module_name} from disk")
                    if module_dir.name == "modules":
                        namespace = f"bbot.modules"
                    else:
                        namespace = f"bbot.modules.{module_dir.name}"
                    try:
                        preloaded = self.preload_module(module_file)
                        module_type = "scan"
                        if module_dir.name in ("output", "internal"):
                            module_type = str(module_dir.name)
                        elif module_dir.name not in ("modules"):
                            flags = set(preloaded["flags"] + [module_dir.name])
                            preloaded["flags"] = sorted(flags)

                        # derive module dependencies from watched event types (only for scan modules)
                        if module_type == "scan":
                            for event_type in preloaded["watched_events"]:
                                if event_type in self.default_module_deps:
                                    deps_modules = set(preloaded.get("deps", {}).get("modules", []))
                                    deps_modules.add(self.default_module_deps[event_type])
                                    preloaded["deps"]["modules"] = sorted(deps_modules)

                        preloaded["type"] = module_type
                        preloaded["namespace"] = namespace
                        preloaded["cache_key"] = module_cache_key

                    except Exception:
                        log_to_stderr(f"Error preloading {module_file}\n\n{traceback.format_exc()}", level="CRITICAL")
                        log_to_stderr(f"Error in {module_file.name}", level="CRITICAL")
                        sys.exit(1)

                self.all_module_choices.add(module_name)
                module_type = preloaded.get("type", "scan")
                if module_type == "scan":
                    self.scan_module_choices.add(module_name)
                elif module_type == "output":
                    self.output_module_choices.add(module_name)
                elif module_type == "internal":
                    self.internal_module_choices.add(module_name)

                flags = preloaded.get("flags", [])
                self.flag_choices.update(set(flags))

                self.__preloaded[module_name] = preloaded
                config = OmegaConf.create(preloaded.get("config", {}))
                self._configs[module_name] = config

            self._module_dirs_preloaded.add(module_dir)

        # update default config with module defaults
        module_config = omegaconf.OmegaConf.create(
            {
                "modules": self.configs(),
            }
        )
        self.core.merge_default(module_config)

        return new_modules

    @property
    def preload_cache(self):
        if self._preload_cache is None:
            self._preload_cache = {}
            if self.preload_cache_file.is_file():
                with suppress(Exception):
                    with open(self.preload_cache_file, "rb") as f:
                        self._preload_cache = pickle.load(f)
        return self._preload_cache

    @preload_cache.setter
    def preload_cache(self, value):
        self._preload_cache = value
        mkdir(self.preload_cache_file.parent)
        with open(self.preload_cache_file, "wb") as f:
            pickle.dump(self._preload_cache, f)

    def save_preload_cache(self):
        self.preload_cache = self.__preloaded

    @property
    def _preloaded(self):
        return self.__preloaded

    def get_recursive_dirs(self, *dirs):
        dirs = set(Path(d).resolve() for d in dirs)
        for d in list(dirs):
            if not d.is_dir():
                continue
            for p in d.iterdir():
                if p.is_dir() and self.module_dir_regex.match(p.name):
                    dirs.update(self.get_recursive_dirs(p))
        return dirs

    def preloaded(self, type=None):
        preloaded = {}
        if type is not None:
            preloaded = {k: v for k, v in self._preloaded.items() if self.check_type(k, type)}
        else:
            preloaded = dict(self._preloaded)
        return preloaded

    def configs(self, type=None):
        configs = {}
        if type is not None:
            configs = {k: v for k, v in self._configs.items() if self.check_type(k, type)}
        else:
            configs = dict(self._configs)
        return OmegaConf.create(configs)

    def find_and_replace(self, **kwargs):
        self.__preloaded = search_format_dict(self.__preloaded, **kwargs)
        self._shared_deps = search_format_dict(self._shared_deps, **kwargs)

    def check_type(self, module, type):
        return self._preloaded[module]["type"] == type

    def preload_module(self, module_file):
        """
        Preloads a BBOT module to gather its meta-information and dependencies.

        This function reads a BBOT module file, extracts its attributes such as
        events watched and produced, flags, meta-information, and dependencies.

        Args:
            module_file (str): Path to the BBOT module file.

        Returns:
            dict: A dictionary containing meta-information and dependencies for the module.

        Examples:
            >>> preload_module("bbot/modules/wappalyzer.py")
            {
                "watched_events": [
                    "HTTP_RESPONSE"
                ],
                "produced_events": [
                    "TECHNOLOGY"
                ],
                "flags": [
                    "active",
                    "safe",
                    "web-basic",
                    "web-thorough"
                ],
                "meta": {
                    "description": "Extract technologies from web responses"
                },
                "config": {},
                "options_desc": {},
                "hash": "d5a88dd3866c876b81939c920bf4959716e2a374",
                "deps": {
                    "modules": [
                        "httpx"
                    ]
                    "pip": [
                        "python-Wappalyzer~=0.3.1"
                    ],
                    "pip_constraints": [],
                    "shell": [],
                    "apt": [],
                    "ansible": []
                },
                "sudo": false
            }
        """
        watched_events = set()
        produced_events = set()
        flags = set()
        meta = {}
        deps_modules = set()
        deps_pip = []
        deps_pip_constraints = []
        deps_shell = []
        deps_apt = []
        deps_common = []
        ansible_tasks = []
        python_code = open(module_file).read()
        # take a hash of the code so we can keep track of when it changes
        module_hash = sha1(python_code).hexdigest()
        parsed_code = ast.parse(python_code)
        config = {}
        options_desc = {}
        for root_element in parsed_code.body:
            # look for classes
            if type(root_element) == ast.ClassDef:
                for class_attr in root_element.body:

                    # class attributes that are dictionaries
                    if type(class_attr) == ast.Assign and type(class_attr.value) == ast.Dict:
                        # module options
                        if any([target.id == "options" for target in class_attr.targets]):
                            config.update(ast.literal_eval(class_attr.value))
                        # module options
                        elif any([target.id == "options_desc" for target in class_attr.targets]):
                            options_desc.update(ast.literal_eval(class_attr.value))
                        # module metadata
                        elif any([target.id == "meta" for target in class_attr.targets]):
                            meta = ast.literal_eval(class_attr.value)

                    # class attributes that are lists
                    if type(class_attr) == ast.Assign and type(class_attr.value) == ast.List:
                        # flags
                        if any([target.id == "flags" for target in class_attr.targets]):
                            for flag in class_attr.value.elts:
                                if type(flag.value) == str:
                                    flags.add(flag.value)
                        # watched events
                        elif any([target.id == "watched_events" for target in class_attr.targets]):
                            for event_type in class_attr.value.elts:
                                if type(event_type.value) == str:
                                    watched_events.add(event_type.value)
                        # produced events
                        elif any([target.id == "produced_events" for target in class_attr.targets]):
                            for event_type in class_attr.value.elts:
                                if type(event_type.value) == str:
                                    produced_events.add(event_type.value)

                        # bbot module dependencies
                        elif any([target.id == "deps_modules" for target in class_attr.targets]):
                            for dep_module in class_attr.value.elts:
                                if type(dep_module.value) == str:
                                    deps_modules.add(dep_module.value)
                        # python dependencies
                        elif any([target.id == "deps_pip" for target in class_attr.targets]):
                            for dep_pip in class_attr.value.elts:
                                if type(dep_pip.value) == str:
                                    deps_pip.append(dep_pip.value)
                        elif any([target.id == "deps_pip_constraints" for target in class_attr.targets]):
                            for dep_pip in class_attr.value.elts:
                                if type(dep_pip.value) == str:
                                    deps_pip_constraints.append(dep_pip.value)
                        # apt dependencies
                        elif any([target.id == "deps_apt" for target in class_attr.targets]):
                            for dep_apt in class_attr.value.elts:
                                if type(dep_apt.value) == str:
                                    deps_apt.append(dep_apt.value)
                        # bash dependencies
                        elif any([target.id == "deps_shell" for target in class_attr.targets]):
                            for dep_shell in class_attr.value.elts:
                                deps_shell.append(ast.literal_eval(dep_shell))
                        # ansible playbook
                        elif any([target.id == "deps_ansible" for target in class_attr.targets]):
                            ansible_tasks = ast.literal_eval(class_attr.value)
                        # shared/common module dependencies
                        elif any([target.id == "deps_common" for target in class_attr.targets]):
                            for dep_common in class_attr.value.elts:
                                if type(dep_common.value) == str:
                                    deps_common.append(dep_common.value)

        for task in ansible_tasks:
            if not "become" in task:
                task["become"] = False
            # don't sudo brew
            elif os_platform() == "darwin" and ("package" in task and task.get("become", False) == True):
                task["become"] = False

        preloaded_data = {
            "path": str(module_file.resolve()),
            "watched_events": sorted(watched_events),
            "produced_events": sorted(produced_events),
            "flags": sorted(flags),
            "meta": meta,
            "config": config,
            "options_desc": options_desc,
            "hash": module_hash,
            "deps": {
                "modules": sorted(deps_modules),
                "pip": deps_pip,
                "pip_constraints": deps_pip_constraints,
                "shell": deps_shell,
                "apt": deps_apt,
                "ansible": ansible_tasks,
                "common": deps_common,
            },
            "sudo": len(deps_apt) > 0,
        }
        ansible_task_list = list(ansible_tasks)
        for dep_common in deps_common:
            try:
                ansible_task_list.extend(self._shared_deps[dep_common])
            except KeyError:
                common_choices = ",".join(self._shared_deps)
                raise BBOTError(
                    f'Error while preloading module "{module_file}": No shared dependency named "{dep_common}" (choices: {common_choices})'
                )
        for ansible_task in ansible_task_list:
            if any(x == True for x in search_dict_by_key("become", ansible_task)) or any(
                x == True for x in search_dict_by_key("ansible_become", ansible_tasks)
            ):
                preloaded_data["sudo"] = True
        return preloaded_data

    def load_modules(self, module_names):
        modules = {}
        for module_name in module_names:
            module = self.load_module(module_name)
            modules[module_name] = module
            self._modules[module_name] = module
        return modules

    def load_module(self, module_name):
        """Loads a BBOT module by its name.

        Imports the module from its namespace, locates its class, and returns it.
        Identifies modules based on the presence of `watched_events` and `produced_events` attributes.

        Args:
            module_name (str): The name of the module to load.

        Returns:
            object: The loaded module class object.

        Examples:
            >>> module = load_module("example_module")
            >>> isinstance(module, object)
            True
        """
        preloaded = self._preloaded[module_name]
        namespace = preloaded["namespace"]
        try:
            module_path = preloaded["path"]
        except KeyError:
            module_path = preloaded["cache_key"][0]
        full_namespace = f"{namespace}.{module_name}"

        spec = importlib.util.spec_from_file_location(full_namespace, module_path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[full_namespace] = module
        spec.loader.exec_module(module)

        # for every top-level variable in the .py file
        for variable in module.__dict__.keys():
            # get its value
            value = getattr(module, variable)
            with suppress(AttributeError):
                # if it has watched_events and produced_events
                if all(
                    type(a) == list
                    for a in (getattr(value, "watched_events", None), getattr(value, "produced_events", None))
                ):
                    # and if its variable name matches its filename
                    if value.__name__.lower() == module_name.lower():
                        value._name = module_name
                        # then we have a module
                        return value

    def recommend_dependencies(self, modules):
        """
        Returns a dictionary containing missing dependencies and their suggested resolutions

        Needs work. For this we should probably be building a dependency graph
        """
        resolve_choices = {}
        # step 1: build a dictionary containing event types and their associated modules
        # {"IP_ADDRESS": set("masscan", "ipneighbor", ...)}
        watched = {}
        produced = {}
        for modname in modules:
            preloaded = self._preloaded.get(modname)
            if preloaded:
                for event_type in preloaded.get("watched_events", []):
                    self.add_or_create(watched, event_type, modname)
                for event_type in preloaded.get("produced_events", []):
                    self.add_or_create(produced, event_type, modname)
        watched_all = {}
        produced_all = {}
        for modname, preloaded in self.preloaded().items():
            if preloaded:
                for event_type in preloaded.get("watched_events", []):
                    self.add_or_create(watched_all, event_type, modname)
                for event_type in preloaded.get("produced_events", []):
                    self.add_or_create(produced_all, event_type, modname)

        # step 2: check to see if there are missing dependencies
        for modname in modules:
            preloaded = self._preloaded.get(modname)
            module_type = preloaded.get("type", "unknown")
            if module_type != "scan":
                continue
            watched_events = preloaded.get("watched_events", [])
            missing_deps = {e: not self.check_dependency(e, modname, produced) for e in watched_events}
            if all(missing_deps.values()):
                for event_type in watched_events:
                    if event_type == "SCAN":
                        continue
                    choices = produced_all.get(event_type, [])
                    choices = set(choices)
                    with suppress(KeyError):
                        choices.remove(modname)
                    if event_type not in resolve_choices:
                        resolve_choices[event_type] = dict()
                    deps = resolve_choices[event_type]
                    self.add_or_create(deps, "required_by", modname)
                    for c in choices:
                        choice_type = self._preloaded.get(c, {}).get("type", "unknown")
                        if choice_type == "scan":
                            self.add_or_create(deps, "recommended", c)

        return resolve_choices

    def check_dependency(self, event_type, modname, produced):
        if event_type not in produced:
            return False
        if produced[event_type] == {modname}:
            return False
        return True

    @staticmethod
    def add_or_create(d, k, *items):
        try:
            d[k].update(set(items))
        except KeyError:
            d[k] = set(items)

    def modules_table(self, modules=None, mod_type=None, include_author=False, include_created_date=False):
        """Generates a table of module information.

        Constructs a table to display information such as module name, type, and event details.

        Args:
            modules (list, optional): List of module names to include in the table.
            mod_type (str, optional): Type of modules to include ('scan', 'output', 'internal').

        Returns:
            str: A formatted table string.

        Examples:
            >>> print(modules_table(["portscan"]))
            +----------+--------+-----------------+------------------------------+-------------------------------+----------------------+-------------------+
            | Module   | Type   | Needs API Key   | Description                  | Flags                         | Consumed Events      | Produced Events   |
            +==========+========+=================+==============================+===============================+======================+===================+
            | portscan | scan   | No              | Execute port scans           | active, aggressive, portscan, | DNS_NAME, IP_ADDRESS | OPEN_TCP_PORT     |
            |          |        |                 |                              | web-thorough                  |                      |                   |
            +----------+--------+-----------------+------------------------------+-------------------------------+----------------------+-------------------+
        """

        table = []
        header = ["Module", "Type", "Needs API Key", "Description", "Flags", "Consumed Events", "Produced Events"]
        if include_author:
            header.append("Author")
        if include_created_date:
            header.append("Created Date")
        maxcolwidths = [20, 10, 5, 30, 30, 20, 20]
        for module_name, preloaded in self.filter_modules(modules, mod_type):
            module_type = preloaded["type"]
            consumed_events = sorted(preloaded.get("watched_events", []))
            produced_events = sorted(preloaded.get("produced_events", []))
            flags = sorted(preloaded.get("flags", []))
            api_key_required = ""
            meta = preloaded.get("meta", {})
            api_key_required = "Yes" if meta.get("auth_required", False) else "No"
            description = meta.get("description", "")
            row = [
                module_name,
                module_type,
                api_key_required,
                description,
                ", ".join(flags),
                ", ".join(consumed_events),
                ", ".join(produced_events),
            ]
            if include_author:
                author = meta.get("author", "")
                row.append(author)
            if include_created_date:
                created_date = meta.get("created_date", "")
                row.append(created_date)
            table.append(row)
        return make_table(table, header, maxcolwidths=maxcolwidths)

    def modules_options(self, modules=None, mod_type=None):
        """
        Return a list of module options
        """
        modules_options = {}
        for module_name, preloaded in self.filter_modules(modules, mod_type):
            modules_options[module_name] = []
            module_options = preloaded["config"]
            module_options_desc = preloaded["options_desc"]
            for k, v in sorted(module_options.items(), key=lambda x: x[0]):
                option_name = f"modules.{module_name}.{k}"
                option_type = type(v).__name__
                option_description = module_options_desc[k]
                modules_options[module_name].append((option_name, option_type, option_description, str(v)))
        return modules_options

    def modules_options_table(self, modules=None, mod_type=None):
        table = []
        header = ["Config Option", "Type", "Description", "Default"]
        for module_name, module_options in self.modules_options(modules, mod_type).items():
            table += module_options
        return make_table(table, header)

    def flags(self, flags=None):
        _flags = {}
        for module_name, preloaded in self.preloaded().items():
            for flag in preloaded.get("flags", []):
                if not flags or flag in flags:
                    try:
                        _flags[flag].add(module_name)
                    except KeyError:
                        _flags[flag] = {module_name}

        _flags = sorted(_flags.items(), key=lambda x: x[0])
        _flags = sorted(_flags, key=lambda x: len(x[-1]), reverse=True)
        return _flags

    def flags_table(self, flags=None):
        table = []
        header = ["Flag", "# Modules", "Description", "Modules"]
        maxcolwidths = [20, 5, 40, 80]
        _flags = self.flags(flags=flags)
        for flag, modules in _flags:
            description = flag_descriptions.get(flag, "")
            table.append([flag, f"{len(modules)}", description, ", ".join(sorted(modules))])
        return make_table(table, header, maxcolwidths=maxcolwidths)

    def events(self):
        consuming_events = {}
        producing_events = {}
        for module_name, preloaded in self.preloaded().items():
            consumed = preloaded.get("watched_events", [])
            produced = preloaded.get("produced_events", [])
            for c in consumed:
                try:
                    consuming_events[c].add(module_name)
                except KeyError:
                    consuming_events[c] = {module_name}
            for c in produced:
                try:
                    producing_events[c].add(module_name)
                except KeyError:
                    producing_events[c] = {module_name}
        return consuming_events, producing_events

    def events_table(self):
        table = []
        header = ["Event Type", "# Consuming Modules", "# Producing Modules", "Consuming Modules", "Producing Modules"]
        consuming_events, producing_events = self.events()
        all_event_types = sorted(set(consuming_events).union(set(producing_events)))
        for e in all_event_types:
            consuming = sorted(consuming_events.get(e, []))
            producing = sorted(producing_events.get(e, []))
            table.append([e, len(consuming), len(producing), ", ".join(consuming), ", ".join(producing)])
        return make_table(table, header)

    def filter_modules(self, modules=None, mod_type=None):
        if modules is None:
            module_list = list(self.preloaded(type=mod_type).items())
        else:
            module_list = [(m, self._preloaded[m]) for m in modules]
        module_list.sort(key=lambda x: x[0])
        module_list.sort(key=lambda x: "passive" in x[-1]["flags"])
        module_list.sort(key=lambda x: x[-1]["type"], reverse=True)
        return module_list

    def ensure_config_files(self):
        files = self.core.files_config
        mkdir(files.config_dir)

        comment_notice = (
            "# NOTICE: THESE ENTRIES ARE COMMENTED BY DEFAULT\n"
            + "# Please be sure to uncomment when inserting API keys, etc.\n"
        )

        config_obj = OmegaConf.to_object(self.core.default_config)

        # ensure bbot.yml
        if not files.config_filename.exists():
            log_to_stderr(f"Creating BBOT config at {files.config_filename}")
            no_secrets_config = self.core.no_secrets_config(config_obj)
            yaml = OmegaConf.to_yaml(no_secrets_config)
            yaml = comment_notice + "\n".join(f"# {line}" for line in yaml.splitlines())
            with open(str(files.config_filename), "w") as f:
                f.write(yaml)

        # ensure secrets.yml
        if not files.secrets_filename.exists():
            log_to_stderr(f"Creating BBOT secrets at {files.secrets_filename}")
            secrets_only_config = self.core.secrets_only_config(config_obj)
            yaml = OmegaConf.to_yaml(secrets_only_config)
            yaml = comment_notice + "\n".join(f"# {line}" for line in yaml.splitlines())
            with open(str(files.secrets_filename), "w") as f:
                f.write(yaml)
            files.secrets_filename.chmod(0o600)


MODULE_LOADER = ModuleLoader()
