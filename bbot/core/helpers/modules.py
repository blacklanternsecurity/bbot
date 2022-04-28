import ast
from .misc import list_files
from ..errors import ModuleLoadError


def file_filter(file):
    return file.suffix.lower() == ".py" and file.stem not in ["base", "__init__"]


def preload_modules(module_dir):
    preloaded_modules = dict()
    for module_file in list_files(module_dir, filter=file_filter):
        try:
            preloaded_modules[module_file.stem] = preload_module(module_file)
        except Exception:
            # if there's a parsing error, try importing the module to give the user the most info
            namespace = "bbot.modules"
            if module_dir.name == "output":
                namespace = "bbot.modules.output"
            load_modules([module_file.stem], namespace=namespace)
            continue
    return preloaded_modules


def preload_module(module_file):
    python_deps = []
    shell_deps = []
    python_code = open(module_file).read()
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
                    # python dependencies
                    if any([target.id == "deps_python" for target in class_attr.targets]):
                        for python_dep in class_attr.value.elts:
                            if type(python_dep.value) == str:
                                python_deps.append(python_dep.value)
                    # bash dependencies
                    elif any([target.id == "deps_shell" for target in class_attr.targets]):
                        for shell_dep in class_attr.value.elts:
                            if type(shell_dep.value) == str:
                                shell_deps.append(shell_dep.value)
    return {"config": config, "deps": {"python": python_deps, "shell": shell_deps}}


def load_modules(module_names, namespace):

    import importlib

    if namespace == "bbot.modules":
        from ...modules.base import BaseModule

        base_module_class = BaseModule
    elif namespace == "bbot.modules.output":
        from ...modules.output.base import BaseOutputModule

        base_module_class = BaseOutputModule
    else:
        raise ModuleLoadError(f'Invalid module namespace "{namespace}"')

    modules = {}
    for module_name in module_names:
        module_variables = importlib.import_module(f"{namespace}.{module_name}", "bbot")
        for variable in module_variables.__dict__.keys():
            value = getattr(module_variables, variable)
            try:
                if base_module_class in getattr(value, "__bases__", []):
                    value._name = module_name
                    modules[module_name] = value
                    break
            except AttributeError:
                continue
    return modules
