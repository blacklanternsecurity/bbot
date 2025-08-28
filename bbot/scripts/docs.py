#!/usr/bin/env python3

import os
import re
import json
import yaml
from pathlib import Path

from bbot import Preset
from bbot.core.modules import MODULE_LOADER


DEFAULT_PRESET = Preset()

os.environ["BBOT_TABLE_FORMAT"] = "github"


# Make a regex pattern which will match any group of non-space characters that include a blacklisted character
blacklist_chars = ["<", ">"]
blacklist_re = re.compile(r"\|([^|]*[" + re.escape("".join(blacklist_chars)) + r"][^|]*)\|")

bbot_code_dir = Path(__file__).parent.parent.parent


def gen_chord_data():
    # This function generates the dataset for the chord graph in the documentation
    #  showing relationships between BBOT modules and their consumed/produced event types
    preloaded_mods = sorted(MODULE_LOADER.preloaded().items(), key=lambda x: x[0])

    entity_lookup_table = {}
    rels = []
    entities = {}
    entity_counter = 1

    def add_entity(entity, parent_id):
        if entity not in entity_lookup_table:
            nonlocal entity_counter
            e_id = entity_counter
            entity_counter += 1
            entity_lookup_table[entity] = e_id
            entity_lookup_table[e_id] = entity
            entities[e_id] = {"id": e_id, "name": entity, "parent": parent_id, "consumes": [], "produces": []}
        return entity_lookup_table[entity]

    # create entities for all the modules and event types
    for module, preloaded in preloaded_mods:
        watched = [e for e in preloaded["watched_events"] if e != "*"]
        produced = [e for e in preloaded["produced_events"] if e != "*"]
        if watched or produced:
            m_id = add_entity(module, 99999999)
            for event_type in watched:
                e_id = add_entity(event_type, 88888888)
                entities[m_id]["consumes"].append(e_id)
                entities[e_id]["consumes"].append(m_id)
            for event_type in produced:
                e_id = add_entity(event_type, 88888888)
                entities[m_id]["produces"].append(e_id)
                entities[e_id]["produces"].append(m_id)

    def add_rel(incoming, outgoing, t):
        if incoming == "*" or outgoing == "*":
            return
        i_id = entity_lookup_table[incoming]
        o_id = entity_lookup_table[outgoing]
        rels.append({"source": i_id, "target": o_id, "type": t})

    # create all the module <--> event type relationships
    for module, preloaded in preloaded_mods:
        for event_type in preloaded["watched_events"]:
            add_rel(module, event_type, "consumes")
        for event_type in preloaded["produced_events"]:
            add_rel(event_type, module, "produces")

    # write them to JSON files
    data_dir = Path(__file__).parent.parent.parent / "docs" / "data" / "chord_graph"
    data_dir.mkdir(parents=True, exist_ok=True)
    entity_file = data_dir / "entities.json"
    rels_file = data_dir / "rels.json"

    entities = [
        {"id": 77777777, "name": "root"},
        {"id": 99999999, "name": "module", "parent": 77777777},
        {"id": 88888888, "name": "event_type", "parent": 77777777},
    ] + sorted(entities.values(), key=lambda x: x["name"])

    with open(entity_file, "w") as f:
        json.dump(entities, f, indent=4)

    with open(rels_file, "w") as f:
        json.dump(rels, f, indent=4)


def homedir_collapseuser(f):
    f = Path(f)
    home_dir = Path.home()
    if f.is_relative_to(home_dir):
        return Path("~") / f.relative_to(home_dir)
    return f


def enclose_tags(text):
    # Use re.sub() to replace matched words with the same words enclosed in backticks
    result = blacklist_re.sub(r"|`\1`|", text)
    return result


def find_replace_markdown(content, keyword, replace):
    begin_re = re.compile(r"<!--\s*" + keyword + r"\s*-->", re.I)
    end_re = re.compile(r"<!--\s*END\s+" + keyword + r"\s*-->", re.I)

    begin_match = begin_re.search(content)
    end_match = end_re.search(content)

    new_content = str(content)
    if begin_match and end_match:
        start_index = begin_match.span()[-1] + 1
        end_index = end_match.span()[0] - 1
        new_content = new_content[:start_index] + enclose_tags(replace) + new_content[end_index:]
    return new_content


def find_replace_file(file, keyword, replace):
    with open(file) as f:
        content = f.read()
        new_content = find_replace_markdown(content, keyword, replace)
    if new_content != content:
        if "BBOT_TESTING" not in os.environ:
            with open(file, "w") as f:
                f.write(new_content)


def update_docs():
    md_files = [p for p in bbot_code_dir.glob("**/*.md") if p.is_file()]

    def update_md_files(keyword, s):
        for file in md_files:
            find_replace_file(file, keyword, s)

    def update_individual_module_options():
        regex = re.compile("BBOT MODULE OPTIONS ([A-Z_]+)")
        for file in md_files:
            with open(file) as f:
                content = f.read()
            for match in regex.finditer(content):
                module_name = match.groups()[0].lower()
                bbot_module_options_table = DEFAULT_PRESET.module_loader.modules_options_table(modules=[module_name])
                find_replace_file(file, f"BBOT MODULE OPTIONS {module_name.upper()}", bbot_module_options_table)

    # Example commands
    bbot_example_commands = []
    for title, description, command in DEFAULT_PRESET.args.scan_examples:
        example = ""
        example += f"**{title}:**\n\n"
        # example += f"{description}\n"
        example += f"```bash\n# {description}\n{command}\n```"
        bbot_example_commands.append(example)
    bbot_example_commands = "\n\n".join(bbot_example_commands)
    assert len(bbot_example_commands.splitlines()) > 10
    update_md_files("BBOT EXAMPLE COMMANDS", bbot_example_commands)

    # Help output
    bbot_help_output = DEFAULT_PRESET.args.parser.format_help().replace("docs.py", "bbot")
    bbot_help_output = f"```text\n{bbot_help_output}\n```"
    assert len(bbot_help_output.splitlines()) > 50
    update_md_files("BBOT HELP OUTPUT", bbot_help_output)

    # BBOT events
    bbot_event_table = DEFAULT_PRESET.module_loader.events_table()
    assert len(bbot_event_table.splitlines()) > 10
    update_md_files("BBOT EVENTS", bbot_event_table)

    # BBOT modules
    bbot_module_table = DEFAULT_PRESET.module_loader.modules_table(include_author=True, include_created_date=True)
    assert len(bbot_module_table.splitlines()) > 50
    update_md_files("BBOT MODULES", bbot_module_table)

    # BBOT output modules
    bbot_output_module_table = DEFAULT_PRESET.module_loader.modules_table(
        mod_type="output", include_author=True, include_created_date=True
    )
    assert len(bbot_output_module_table.splitlines()) > 10
    update_md_files("BBOT OUTPUT MODULES", bbot_output_module_table)

    # BBOT universal module options
    from bbot.scanner.preset.args import universal_module_options

    universal_module_options_table = ""
    for option, description in universal_module_options.items():
        universal_module_options_table += f"**{option}**: {description}\n"
    update_md_files("BBOT UNIVERSAL MODULE OPTIONS", universal_module_options_table)

    # BBOT module options
    bbot_module_options_table = DEFAULT_PRESET.module_loader.modules_options_table()
    assert len(bbot_module_options_table.splitlines()) > 100
    update_md_files("BBOT MODULE OPTIONS", bbot_module_options_table)
    update_individual_module_options()

    # BBOT module flags
    bbot_module_flags_table = DEFAULT_PRESET.module_loader.flags_table()
    assert len(bbot_module_flags_table.splitlines()) > 10
    update_md_files("BBOT MODULE FLAGS", bbot_module_flags_table)

    # BBOT presets
    bbot_presets_table = DEFAULT_PRESET.presets_table(include_modules=True)
    assert len(bbot_presets_table.splitlines()) > 5
    update_md_files("BBOT PRESETS", bbot_presets_table)

    # BBOT presets
    for _, (loaded_preset, category, preset_path, original_filename) in DEFAULT_PRESET.all_presets.items():
        str_category = "" if not category else f"/{category}"
        filename = f"~/.bbot/presets{str_category}/{original_filename.name}"
        preset_yaml = f"""
```yaml title={filename}
{loaded_preset._yaml_str}
```
"""
        preset_yaml_expandable = f"""
<details>
<summary><b><code>{original_filename.name}</code></b></summary>

```yaml
{loaded_preset._yaml_str}
```

</details>
"""
        update_md_files(f"BBOT {loaded_preset.name.upper()} PRESET", preset_yaml)
        update_md_files(f"BBOT {loaded_preset.name.upper()} PRESET EXPANDABLE", preset_yaml_expandable)

    content = []
    for _, (loaded_preset, category, preset_path, original_filename) in DEFAULT_PRESET.all_presets.items():
        yaml_str = loaded_preset._yaml_str
        indent = " " * 4
        yaml_str = f"\n{indent}".join(yaml_str.splitlines())
        str_category = "" if not category else f"/{category}"
        filename = f"~/.bbot/presets{str_category}/{original_filename.name}"

        num_modules = len(loaded_preset.scan_modules)
        modules = ", ".join(sorted([f"`{m}`" for m in loaded_preset.scan_modules]))
        category = f"Category: {category}" if category else ""

        content.append(
            f"""## **{loaded_preset.name}**

{loaded_preset.description}

??? note "`{original_filename.name}`"
    ```yaml title="{filename}"
    {yaml_str}
    ```

{category}

Modules: [{num_modules:,}]("{modules}")"""
        )
    assert len(content) > 5
    update_md_files("BBOT PRESET YAML", "\n\n".join(content))

    # Default config
    default_config_file = bbot_code_dir / "bbot" / "defaults.yml"
    with open(default_config_file) as f:
        default_config_yml = f.read()
    default_config_yml = f'```yaml title="defaults.yml"\n{default_config_yml}\n```'
    assert len(default_config_yml.splitlines()) > 20
    update_md_files("BBOT DEFAULT CONFIG", default_config_yml)

    # Table of Contents
    base_url = "https://www.blacklanternsecurity.com/bbot/Stable"

    def format_section(section_title, section_path):
        path = section_path.split("index.md")[0]
        path = path.split(".md")[0]
        return f"- [{section_title}]({base_url}/{path})\n"

    bbot_docs_toc = ""

    def update_toc(section, level=0):
        nonlocal bbot_docs_toc
        indent = " " * 4 * level
        if isinstance(section, dict):
            for section_title, subsections in section.items():
                if isinstance(subsections, str):
                    bbot_docs_toc += f"{indent}{format_section(section_title, subsections)}"
                else:
                    bbot_docs_toc += f"{indent}- **{section_title}**\n"
                    for subsection in subsections:
                        update_toc(subsection, level=level + 1)

    mkdocs_yml_file = bbot_code_dir / "mkdocs.yml"
    yaml.SafeLoader.add_constructor(
        "tag:yaml.org,2002:python/name:pymdownx.superfences.fence_code_format", lambda x, y: {}
    )

    with open(mkdocs_yml_file, "r") as f:
        mkdocs_yaml = yaml.safe_load(f)
        nav = mkdocs_yaml["nav"]
        for section in nav:
            update_toc(section)
    bbot_docs_toc = bbot_docs_toc.strip()
    # assert len(bbot_docs_toc.splitlines()) == 2
    update_md_files("BBOT DOCS TOC", bbot_docs_toc)

    # generate data for chord graph
    gen_chord_data()


update_docs()
