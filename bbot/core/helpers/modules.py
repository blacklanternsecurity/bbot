import ast
import sys
import importlib
import traceback
from pathlib import Path
from omegaconf import OmegaConf
from contextlib import suppress

from ..flags import flag_descriptions
from .misc import list_files, sha1, search_dict_by_key, search_format_dict, make_table, os_platform


class ModuleLoader:
    """
    Main class responsible for loading BBOT modules.

    This class is in charge of preloading modules to determine their dependencies.
    Once dependencies are identified, they are installed before the actual module is imported.
    This ensures that all requisite libraries and components are available for the module to function correctly.
    """

    def __init__(self):
        self._preloaded = {}
        self._preloaded_orig = None
        self._modules = {}
        self._configs = {}

    def file_filter(self, file):
        file = file.resolve()
        if "templates" in file.parts:
            return False
        return file.suffix.lower() == ".py" and file.stem not in ["base", "__init__"]

    def preload(self, module_dir):
        """Preloads all modules within a directory.

        This function recursively iterates through each file in the specified directory
        and preloads the BBOT module to gather its meta-information and dependencies.

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
        module_dir = Path(module_dir)
        for module_file in list_files(module_dir, filter=self.file_filter):
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
                    preloaded["flags"] = list(set(preloaded["flags"] + [module_dir.name]))
                preloaded["type"] = module_type
                preloaded["namespace"] = namespace
                config = OmegaConf.create(preloaded.get("config", {}))
                self._configs[module_file.stem] = config
                self._preloaded[module_file.stem] = preloaded
            except Exception:
                print(f"[CRIT] Error preloading {module_file}\n\n{traceback.format_exc()}")
                print(f"[CRIT] Error in {module_file.name}")
                sys.exit(1)

        return self._preloaded

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
        if self._preloaded_orig is None:
            self._preloaded_orig = dict(self._preloaded)
        self._preloaded = search_format_dict(self._preloaded_orig, **kwargs)

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
        watched_events = []
        produced_events = []
        flags = []
        meta = {}
        pip_deps = []
        pip_deps_constraints = []
        shell_deps = []
        apt_deps = []
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
                        if any([target.id == "options_desc" for target in class_attr.targets]):
                            options_desc.update(ast.literal_eval(class_attr.value))
                        # module metadata
                        if any([target.id == "meta" for target in class_attr.targets]):
                            meta = ast.literal_eval(class_attr.value)
                    # class attributes that are lists
                    if type(class_attr) == ast.Assign and type(class_attr.value) == ast.List:
                        # flags
                        if any([target.id == "flags" for target in class_attr.targets]):
                            for flag in class_attr.value.elts:
                                if type(flag.value) == str:
                                    flags.append(flag.value)
                        # watched events
                        if any([target.id == "watched_events" for target in class_attr.targets]):
                            for event_type in class_attr.value.elts:
                                if type(event_type.value) == str:
                                    watched_events.append(event_type.value)
                        # produced events
                        if any([target.id == "produced_events" for target in class_attr.targets]):
                            for event_type in class_attr.value.elts:
                                if type(event_type.value) == str:
                                    produced_events.append(event_type.value)
                        # python dependencies
                        if any([target.id == "deps_pip" for target in class_attr.targets]):
                            for python_dep in class_attr.value.elts:
                                if type(python_dep.value) == str:
                                    pip_deps.append(python_dep.value)

                        if any([target.id == "deps_pip_constraints" for target in class_attr.targets]):
                            for python_dep in class_attr.value.elts:
                                if type(python_dep.value) == str:
                                    pip_deps_constraints.append(python_dep.value)

                        # apt dependencies
                        elif any([target.id == "deps_apt" for target in class_attr.targets]):
                            for apt_dep in class_attr.value.elts:
                                if type(apt_dep.value) == str:
                                    apt_deps.append(apt_dep.value)
                        # bash dependencies
                        elif any([target.id == "deps_shell" for target in class_attr.targets]):
                            for shell_dep in class_attr.value.elts:
                                shell_deps.append(ast.literal_eval(shell_dep))
                        # ansible playbook
                        elif any([target.id == "deps_ansible" for target in class_attr.targets]):
                            ansible_tasks = ast.literal_eval(class_attr.value)
        for task in ansible_tasks:
            if not "become" in task:
                task["become"] = False
            # don't sudo brew
            elif os_platform() == "darwin" and ("package" in task and task.get("become", False) == True):
                task["become"] = False
        preloaded_data = {
            "watched_events": watched_events,
            "produced_events": produced_events,
            "flags": flags,
            "meta": meta,
            "config": config,
            "options_desc": options_desc,
            "hash": module_hash,
            "deps": {
                "pip": pip_deps,
                "pip_constraints": pip_deps_constraints,
                "shell": shell_deps,
                "apt": apt_deps,
                "ansible": ansible_tasks,
            },
            "sudo": len(apt_deps) > 0,
        }
        if any(x == True for x in search_dict_by_key("become", ansible_tasks)) or any(
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
        namespace = self._preloaded[module_name]["namespace"]
        import_path = f"{namespace}.{module_name}"
        module_variables = importlib.import_module(import_path, "bbot")

        # for every top-level variable in the .py file
        for variable in module_variables.__dict__.keys():
            # get its value
            value = getattr(module_variables, variable)
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
        # {"IP_ADDRESS": set("nmap", "ipneighbor", ...)}
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

    def modules_table(self, modules=None, mod_type=None):
        """Generates a table of module information.

        Constructs a table to display information such as module name, type, and event details.

        Args:
            modules (list, optional): List of module names to include in the table.
            mod_type (str, optional): Type of modules to include ('scan', 'output', 'internal').

        Returns:
            str: A formatted table string.

        Examples:
            >>> print(modules_table(["nmap"]))
            +----------+--------+-----------------+------------------------------+-------------------------------+----------------------+-------------------+
            | Module   | Type   | Needs API Key   | Description                  | Flags                         | Consumed Events      | Produced Events   |
            +==========+========+=================+==============================+===============================+======================+===================+
            | nmap     | scan   | No              | Execute port scans with nmap | active, aggressive, portscan, | DNS_NAME, IP_ADDRESS | OPEN_TCP_PORT     |
            |          |        |                 |                              | web-thorough                  |                      |                   |
            +----------+--------+-----------------+------------------------------+-------------------------------+----------------------+-------------------+
        """

        table = []
        header = ["Module", "Type", "Needs API Key", "Description", "Flags", "Consumed Events", "Produced Events"]
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
            table.append(
                [
                    module_name,
                    module_type,
                    api_key_required,
                    description,
                    ", ".join(flags),
                    ", ".join(consumed_events),
                    ", ".join(produced_events),
                ]
            )
        return make_table(table, header, maxcolwidths=maxcolwidths)

    def modules_options(self, modules=None, mod_type=None):
        """
        Return a list of module options
        """
        modules_options = {}
        for module_name, preloaded in self.filter_modules(modules, mod_type):
            modules_options[module_name] = []
            module_type = preloaded["type"]
            module_options = preloaded["config"]
            module_options_desc = preloaded["options_desc"]
            for k, v in sorted(module_options.items(), key=lambda x: x[0]):
                module_key = "modules"
                if module_type in ("internal", "output"):
                    module_key = f"{module_type}_modules"
                option_name = f"{module_key}.{module_name}.{k}"
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


module_loader = ModuleLoader()
