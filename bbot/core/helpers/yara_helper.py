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

    async def match(self, compiled_rules, text):
        """
        Given a compiled YARA rule and a body of text, return a list of strings that match the rule
        """
        matched_strings = []
        matches = await self.parent_helper.run_in_executor(compiled_rules.match, data=text)
        if matches:
            for match in matches:
                for string_match in match.strings:
                    for instance in string_match.instances:
                        matched_string = instance.matched_data.decode("utf-8")
                        matched_strings.append(matched_string)
        return matched_strings
