import ast
import importlib
from contextlib import suppress

from .misc import list_files, sha1
from ..errors import ModuleLoadError


def file_filter(file):
    return file.suffix.lower() == ".py" and file.stem not in ["base", "__init__"]


def preload_modules(module_dir):
    preloaded_modules = dict()
    for module_file in list_files(module_dir, filter=file_filter):
        try:
            preloaded_modules[module_file.stem] = preload_module(module_file)
        except Exception:
            import traceback

            print(traceback.format_exc())
            # if there's a parsing error, try importing the module to give the user the most info
            namespace = "bbot.modules"
            if module_dir.name == "output":
                namespace = "bbot.modules.output"
            if module_dir.name == "internal":
                namespace = "bbot.modules.internal"
            load_modules([module_file.stem], namespace=namespace)
            continue
    return preloaded_modules


def preload_module(module_file):
    flags = []
    watched_events = []
    produced_events = []
    pip_deps = []
    shell_deps = []
    apt_deps = []
    ansible_tasks = []
    python_code = open(module_file).read()
    # take a hash of the code so we can keep track of when it changes
    module_hash = sha1(python_code).hexdigest()
    parsed_code = ast.parse(python_code)
    config = {}
    for root_element in parsed_code.body:
        # look for classes
        if type(root_element) == ast.ClassDef:
            for class_attr in root_element.body:
                # class attributes that are dictionaries
                if type(class_attr) == ast.Assign and type(class_attr.value) == ast.Dict:
                    # module options
                    if any([target.id == "options" for target in class_attr.targets]):
                        config.update(ast.literal_eval(class_attr.value))

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
    return {
        "flags": flags,
        "watched_events": watched_events,
        "produced_events": produced_events,
        "config": config,
        "hash": module_hash,
        "deps": {"pip": pip_deps, "shell": shell_deps, "apt": apt_deps, "ansible": ansible_tasks},
    }


def load_modules(module_names, namespace):

    if namespace == "bbot.modules":
        from ...modules.base import BaseModule

        base_module_class = BaseModule
    elif namespace == "bbot.modules.output":
        from ...modules.output.base import BaseOutputModule

        base_module_class = BaseOutputModule
    elif namespace == "bbot.modules.internal":
        from ...modules.internal.base import BaseInternalModule

        base_module_class = BaseInternalModule
    else:
        raise ModuleLoadError(f'Invalid module namespace "{namespace}"')

    modules = {}
    for module_name in module_names:
        module = load_module(module_name, namespace, base_module_class)
        modules[module_name] = module
    return modules


def load_module(module_name, namespace, base_module_class):
    module_variables = importlib.import_module(f"{namespace}.{module_name}", "bbot")
    for variable in module_variables.__dict__.keys():
        value = getattr(module_variables, variable)
        with suppress(AttributeError):
            if base_module_class in getattr(value, "__bases__", []):
                value._name = module_name
                return value
