import yara


class YaraHelper:
    def __init__(self, parent_helper):
        self.parent_helper = parent_helper

    def compile_strings(self, strings: list[str], nocase=False):
        """
        Compile a list of strings into a YARA rule
        """
        # Format each string as a YARA string definition
        yara_strings = []
        for i, s in enumerate(strings):
            s = s.replace('"', '\\"')
            yara_string = f'$s{i} = "{s}"'
            if nocase:
                yara_string += " nocase"
            yara_strings.append(yara_string)
        yara_strings = "\n        ".join(yara_strings)

        # Create the complete YARA rule
        yara_rule = f"""
rule strings_match
{{
    strings:
        {yara_strings}
    condition:
        any of them
}}
"""
        # Compile and return the rule
        return self.compile(source=yara_rule)

    def compile(self, *args, **kwargs):
        return yara.compile(*args, **kwargs)

    async def match(self, compiled_rules, text, full_result=False):
        """
        Given a compiled YARA rule and a body of text, return matches.

        Args:
            compiled_rules: Compiled YARA rules
            text: Text to match against
            full_result (bool): If True, returns full match information including
                              rule names and metadata. If False, returns only matched strings.

        Returns:
            If full_result=False: List[str] of matched strings
            If full_result=True: List[dict] with full match information including:
                - matched_string: The full matched string
                - rule: The name of the matched rule
                - meta: The metadata of the matched rule
        """
        results = []
        matches = await self.parent_helper.run_in_executor(compiled_rules.match, data=text)
        if matches:
            for match in matches:
                for string_match in match.strings:
                    for instance in string_match.instances:
                        matched_string = instance.matched_data.decode("utf-8")
                        if full_result:
                            results.append({"matched_string": matched_string, "rule": match.rule, "meta": match.meta})
                        else:
                            results.append(matched_string)
        return results
