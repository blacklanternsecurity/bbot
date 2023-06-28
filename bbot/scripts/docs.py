#!/usr/bin/env python3

import os
import re
from pathlib import Path

from bbot.modules import module_loader

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
        with open(file, "w") as f:
            f.write(new_content)


def update_docs():
    bbot_code_dir = Path(__file__).parent.parent.parent
    md_files = [p for p in bbot_code_dir.glob("**/*.md") if p.is_file()]

    # BBOT modules
    bbot_module_table = module_loader.modules_table()
    assert len(bbot_module_table.splitlines()) > 50
    for file in md_files:
        find_replace_file(file, "BBOT MODULES", bbot_module_table)

    # BBOT module options
    bbot_module_options_table = module_loader.modules_options_table()
    assert len(bbot_module_options_table.splitlines()) > 100
    for file in md_files:
        find_replace_file(file, "BBOT MODULE OPTIONS", bbot_module_options_table)

    # BBOT module flags
    bbot_module_flags_table = module_loader.flags_table()
    assert len(bbot_module_flags_table.splitlines()) > 10
    for file in md_files:
        find_replace_file(file, "BBOT MODULE FLAGS", bbot_module_flags_table)

    # Default config
    default_config_file = bbot_code_dir / "bbot" / "defaults.yml"
    with open(default_config_file) as f:
        default_config_yml = f.read()
    default_config_yml = f"```yaml\n{default_config_yml}\n```"
    assert len(default_config_yml.splitlines()) > 20
    for file in md_files:
        find_replace_file(file, "BBOT DEFAULT CONFIG", default_config_yml)


update_docs()
