from contextlib import suppress
from collections import defaultdict

from bbot.modules.output.base import BaseOutputModule


class Web_parameters(BaseOutputModule):
    watched_events = ["WEB_PARAMETER"]
    meta = {
        "description": "Output WEB_PARAMETER names to a file",
        "created_date": "2025-01-25",
        "author": "@liquidsec",
    }
    options = {"output_file": "", "include_count": False}
    options_desc = {
        "output_file": "Output to file",
        "include_count": "Include the count of each parameter in the output",
    }

    output_filename = "web_parameters.txt"

    async def setup(self):
        self._prep_output_dir(self.output_filename)
        self.parameter_counts = defaultdict(int)
        return True

    async def handle_event(self, event):
        parameter_name = event.data.get("name", "")
        if parameter_name:
            self.parameter_counts[parameter_name] += 1

    async def cleanup(self):
        if getattr(self, "_file", None) is not None:
            with suppress(Exception):
                self.file.close()

    async def report(self):
        include_count = self.config.get("include_count", False)

        # Sort behavior:
        # - If include_count is True, sort by count (descending) and then alphabetically by name
        # - If include_count is False, sort alphabetically by name only
        sorted_parameters = sorted(
            self.parameter_counts.items(), key=lambda x: (-x[1], x[0]) if include_count else x[0]
        )
        for param, count in sorted_parameters:
            if include_count:
                # Include the count of each parameter in the output
                self.file.write(f"{count}\t{param}\n")
            else:
                # Only include the parameter name, effectively deduplicating by name
                self.file.write(f"{param}\n")
        self.file.flush()
        if getattr(self, "_file", None) is not None:
            self.info(f"Saved web parameters to {self.output_file}")
