import regex as re
from . import misc


class RegexHelper:
    """
    Class for misc CPU-intensive regex operations

    Offloads regex processing to other CPU cores via GIL release + thread pool
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

    async def findall(self, compiled_regex, *args, **kwargs):
        self.ensure_compiled_regex(compiled_regex)
        return await self.parent_helper.run_in_executor(compiled_regex.findall, *args, **kwargs)

    async def finditer(self, compiled_regex, *args, **kwargs):
        self.ensure_compiled_regex(compiled_regex)
        return await self.parent_helper.run_in_executor(self._finditer, compiled_regex, *args, **kwargs)

    async def finditer_multi(self, compiled_regexes, *args, **kwargs):
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
