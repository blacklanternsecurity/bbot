import asyncio
import regex as re
from . import misc


class RegexHelper:
    """
    Class for misc CPU-intensive regex operations

    Offloads regex processing to other CPU cores via GIL release + thread pool

    For quick, one-off regexes, you don't need to use this helper.
    Only use this helper if you're searching large bodies of text
    or if your regex is CPU-intensive
    """

    def __init__(self, parent_helper):
        self.parent_helper = parent_helper

    def ensure_compiled_regex(self, r):
        """
        Make sure a regex has been compiled
        """
        if not isinstance(r, re.Pattern):
            raise ValueError("Regex must be compiled first!")

    def compile(self, *args, **kwargs):
        return re.compile(*args, **kwargs)

    async def search(self, compiled_regex, *args, **kwargs):
        self.ensure_compiled_regex(compiled_regex)
        return await self.parent_helper.run_in_executor(compiled_regex.search, *args, **kwargs)

    async def sub(self, compiled_regex, *args, **kwargs):
        self.ensure_compiled_regex(compiled_regex)
        return await self.parent_helper.run_in_executor(compiled_regex.sub, *args, **kwargs)

    async def findall(self, compiled_regex, *args, **kwargs):
        self.ensure_compiled_regex(compiled_regex)
        return await self.parent_helper.run_in_executor(compiled_regex.findall, *args, **kwargs)

    async def findall_multi(self, compiled_regexes, *args, threads=10, **kwargs):
        """
        Same as findall() but with multiple regexes
        """
        if not isinstance(compiled_regexes, dict):
            raise ValueError('compiled_regexes must be a dictionary like this: {"regex_name": <compiled_regex>}')
        for v in compiled_regexes.values():
            self.ensure_compiled_regex(v)

        tasks = {}

        def new_task(regex_name, r):
            task = self.parent_helper.run_in_executor(r.findall, *args, **kwargs)
            tasks[task] = regex_name

        compiled_regexes = dict(compiled_regexes)
        for _ in range(threads):  # Start initial batch of tasks
            if compiled_regexes:  # Ensure there are args to process
                new_task(*compiled_regexes.popitem())

        while tasks:  # While there are tasks pending
            # Wait for the first task to complete
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

            for task in done:
                result = task.result()
                regex_name = tasks.pop(task)
                yield (regex_name, result)

                if compiled_regexes:  # Start a new task for each one completed, if URLs remain
                    new_task(*compiled_regexes.popitem())

    async def finditer(self, compiled_regex, *args, **kwargs):
        self.ensure_compiled_regex(compiled_regex)
        return await self.parent_helper.run_in_executor(self._finditer, compiled_regex, *args, **kwargs)

    async def finditer_multi(self, compiled_regexes, *args, **kwargs):
        """
        Same as finditer() but with multiple regexes
        """
        for r in compiled_regexes:
            self.ensure_compiled_regex(r)
        return await self.parent_helper.run_in_executor(self._finditer_multi, compiled_regexes, *args, **kwargs)

    def _finditer_multi(self, compiled_regexes, *args, **kwargs):
        matches = []
        for r in compiled_regexes:
            for m in r.finditer(*args, **kwargs):
                matches.append(m)
        return matches

    def _finditer(self, compiled_regex, *args, **kwargs):
        return list(compiled_regex.finditer(*args, **kwargs))

    async def extract_params_html(self, *args, **kwargs):
        return await self.parent_helper.run_in_executor(misc.extract_params_html, *args, **kwargs)

    async def extract_emails(self, *args, **kwargs):
        return await self.parent_helper.run_in_executor(misc.extract_emails, *args, **kwargs)

    async def search_dict_values(self, *args, **kwargs):
        def _search_dict_values(*_args, **_kwargs):
            return list(misc.search_dict_values(*_args, **_kwargs))

        return await self.parent_helper.run_in_executor(_search_dict_values, *args, **kwargs)

    async def recursive_decode(self, *args, **kwargs):
        return await self.parent_helper.run_in_executor(misc.recursive_decode, *args, **kwargs)
