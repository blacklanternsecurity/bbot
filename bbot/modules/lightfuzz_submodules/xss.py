from .base import BaseLightfuzz

import regex as re


class XSSLightfuzz(BaseLightfuzz):
    async def determine_context(self, cookies, html, random_string):
        """
        Determines the context of the random string in the HTML response.
        With XSS, the context is what kind part of the page the injection is occuring in, which determine what payloads might be successful

        https://portswigger.net/web-security/cross-site-scripting/contexts
        """
        between_tags, in_tag_attribute, in_javascript = await self.check_xss_contexts(html, random_string)
        return between_tags, in_tag_attribute, in_javascript

    async def check_xss_contexts(self, html, random_string):
        between_tags = await self.check_between_tags(html, random_string)
        in_tag_attribute = await self.check_in_tag_attribute(html, random_string)
        in_javascript = await self.check_in_javascript(html, random_string)
        return between_tags, in_tag_attribute, in_javascript

    async def check_between_tags(self, html, random_string):
        between_tags_regex = re.compile(rf"<(\/?\w+)[^>]*>.*?{random_string}.*?<\/?\w+>")
        between_tags_match = await self.lightfuzz.helpers.re.search(between_tags_regex, html)
        return bool(between_tags_match)

    async def check_in_tag_attribute(self, html, random_string):
        in_tag_attribute_regex = re.compile(rf'<(\w+)\s+[^>]*?(\w+)="([^"]*?{random_string}[^"]*?)"[^>]*>')
        in_tag_attribute_match = await self.lightfuzz.helpers.re.search(in_tag_attribute_regex, html)
        return bool(in_tag_attribute_match)

    async def check_in_javascript(self, html, random_string):
        in_javascript_regex = re.compile(
            rf"<script\b[^>]*>[^<]*(?:<(?!\/script>)[^<]*)*{random_string}[^<]*(?:<(?!\/script>)[^<]*)*<\/script>"
        )
        in_javascript_match = await self.lightfuzz.helpers.re.search(in_javascript_regex, html)
        return bool(in_javascript_match)

    async def determine_javascript_quote_context(self, target, text):
        quote_patterns = {"double": re.compile(f'"[^"]*{target}[^"]*"'), "single": re.compile(f"'[^']*{target}[^']*'")}
        statements = text.split(";")

        def is_balanced(section, target_index, quote_char):
            left = section[:target_index]
            right = section[target_index + len(target) :]
            return left.count(quote_char) % 2 == 0 and right.count(quote_char) % 2 == 0

        for statement in statements:
            for quote_type, pattern in quote_patterns.items():
                match = await self.lightfuzz.helpers.re.search(pattern, statement)
                if match:
                    context = match.group(0)
                    target_index = context.find(target)
                    opposite_quote = "'" if quote_type == "double" else '"'
                    if is_balanced(context, target_index, opposite_quote):
                        return quote_type
        return "outside"

    async def check_probe(self, cookies, probe, match, context):
        probe_result = await self.standard_probe(self.event.data["type"], cookies, probe)
        if probe_result and match in probe_result.text:
            self.results.append(
                {
                    "type": "FINDING",
                    "description": f"Possible Reflected XSS. Parameter: [{self.event.data['name']}] Context: [{context}] Parameter Type: [{self.event.data['type']}]",
                }
            )
            return True
        return False

    async def fuzz(self):
        lightfuzz_event = self.event.parent
        cookies = self.event.data.get("assigned_cookies", {})

        if (
            lightfuzz_event.type == "WEB_PARAMETER"
            and str(lightfuzz_event.module) == "paramminer_getparams"
            and "http-reflection" not in lightfuzz_event.tags
        ):
            return

        random_string = self.lightfuzz.helpers.rand_string(8)
        reflection_probe_result = await self.standard_probe(self.event.data["type"], cookies, random_string)
        if not reflection_probe_result or random_string not in reflection_probe_result.text:
            return

        between_tags, in_tag_attribute, in_javascript = await self.determine_context(
            cookies, reflection_probe_result.text, random_string
        )
        self.lightfuzz.debug(
            f"determine_context returned: between_tags [{between_tags}], in_tag_attribute [{in_tag_attribute}], in_javascript [{in_javascript}]"
        )

        if between_tags:
            await self.test_between_tags(cookies, random_string)

        if in_tag_attribute:
            await self.test_in_tag_attribute(cookies, random_string)

        if in_javascript:
            await self.test_in_javascript(cookies, random_string, reflection_probe_result)

    async def test_between_tags(self, cookies, random_string):
        tags = ["z", "svg", "img"]
        for tag in tags:
            between_tags_probe = f"<{tag}>{random_string}</{tag}>"
            result = await self.check_probe(
                cookies, between_tags_probe, between_tags_probe, f"Between Tags ({tag} tag)"
            )
            if result:
                break

    async def test_in_tag_attribute(self, cookies, random_string):
        in_tag_attribute_probe = f'{random_string}"'
        in_tag_attribute_match = f'"{random_string}""'
        await self.check_probe(cookies, in_tag_attribute_probe, in_tag_attribute_match, "Tag Attribute")

        in_tag_attribute_probe = f"javascript:{random_string}"
        in_tag_attribute_match = f'action="javascript:{random_string}'
        await self.check_probe(cookies, in_tag_attribute_probe, in_tag_attribute_match, "Form Action Injection")

    async def test_in_javascript(self, cookies, random_string, reflection_probe_result):
        in_javascript_probe = rf"</script><script>{random_string}</script>"
        result = await self.check_probe(cookies, in_javascript_probe, in_javascript_probe, "In Javascript")
        if not result:
            quote_context = await self.determine_javascript_quote_context(random_string, reflection_probe_result.text)

            if quote_context == "outside":
                return

            if quote_context == "single":
                in_javascript_escape_probe = rf"a\';zzzzz({random_string})\\"
                in_javascript_escape_match = rf"a\\';zzzzz({random_string})\\"
            elif quote_context == "double":
                in_javascript_escape_probe = rf"a\";zzzzz({random_string})\\"
                in_javascript_escape_match = rf'a\\";zzzzz({random_string})\\'

            await self.check_probe(
                cookies,
                in_javascript_escape_probe,
                in_javascript_escape_match,
                f"In Javascript (escaping the escape character, {quote_context} quote)",
            )
