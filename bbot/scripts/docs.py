#!/usr/bin/env python3

import os
import re
from pathlib import Path

from bbot.modules import module_loader
from bbot.core.configurator.args import parser, scan_examples

os.environ["BBOT_TABLE_FORMAT"] = "github"


# Make a regex pattern which will match any group of non-space characters that include a blacklisted character
blacklist_chars = ["<", ">"]
blacklist_re = re.compile(r"\|([^|]*[" + re.escape("".join(blacklist_chars)) + r"][^|]*)\|")


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
        if not "BBOT_TESTING" in os.environ:
            with open(file, "w") as f:
                f.write(new_content)


def update_docs():
    bbot_code_dir = Path(__file__).parent.parent.parent
    md_files = [p for p in bbot_code_dir.glob("**/*.md") if p.is_file()]

    def update_md_files(keyword, s):
        for file in md_files:
            find_replace_file(file, keyword, s)

    # Example commands
    bbot_example_commands = []
    for title, description, command in scan_examples:
        example = ""
        example += f"**{title}:**\n"
        # example += f"{description}\n"
        example += f"```bash\n# {description}\n{command}\n```"
        bbot_example_commands.append(example)
    bbot_example_commands = "\n\n".join(bbot_example_commands)
    assert len(bbot_example_commands.splitlines()) > 10
    update_md_files("BBOT EXAMPLE COMMANDS", bbot_example_commands)

    # Help output
    bbot_help_output = parser.format_help().replace("docs.py", "bbot")
    bbot_help_output = f"```text\n{bbot_help_output}\n```"
    assert len(bbot_help_output.splitlines()) > 50
    update_md_files("BBOT HELP OUTPUT", bbot_help_output)

    # BBOT events
    bbot_event_table = module_loader.events_table()
    assert len(bbot_event_table.splitlines()) > 10
    update_md_files("BBOT EVENTS", bbot_event_table)

    # BBOT modules
    bbot_module_table = module_loader.modules_table()
    assert len(bbot_module_table.splitlines()) > 50
    update_md_files("BBOT MODULES", bbot_module_table)

    # BBOT module options
    bbot_module_options_table = module_loader.modules_options_table()
    assert len(bbot_module_options_table.splitlines()) > 100
    update_md_files("BBOT MODULE OPTIONS", bbot_module_options_table)

    # BBOT module flags
    bbot_module_flags_table = module_loader.flags_table()
    assert len(bbot_module_flags_table.splitlines()) > 10
    update_md_files("BBOT MODULE FLAGS", bbot_module_flags_table)

    # Default config
    default_config_file = bbot_code_dir / "bbot" / "defaults.yml"
    with open(default_config_file) as f:
        default_config_yml = f.read()
    default_config_yml = f"```yaml\n{default_config_yml}\n```"
    assert len(default_config_yml.splitlines()) > 20
    update_md_files("BBOT DEFAULT CONFIG", default_config_yml)


update_docs()
