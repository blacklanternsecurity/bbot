from .base import BaseLightfuzz

import regex as re


class XSSLightfuzz(BaseLightfuzz):
    async def determine_context(self, cookies, html, random_string):
        between_tags = False
        in_tag_attribute = False
        in_javascript = False

        between_tags_regex = re.compile(rf"<(\/?\w+)[^>]*>.*?{random_string}.*?<\/?\w+>")
        in_tag_attribute_regex = re.compile(rf'<(\w+)\s+[^>]*?(\w+)="([^"]*?{random_string}[^"]*?)"[^>]*>')
        in_javascript_regex = re.compile(
            rf"<script\b[^>]*>(?:(?!<\/script>)[\s\S])*?{random_string}(?:(?!<\/script>)[\s\S])*?<\/script>"
        )

        between_tags_match = await self.lightfuzz.helpers.re.search(between_tags_regex, html)
        if between_tags_match:
            between_tags = True

        in_tag_attribute_match = await self.lightfuzz.helpers.re.search(in_tag_attribute_regex, html)
        if in_tag_attribute_match:
            in_tag_attribute = True

        in_javascript_match = await self.lightfuzz.helpers.re.search(in_javascript_regex, html)
        if in_javascript_match:
            in_javascript = True

        return between_tags, in_tag_attribute, in_javascript

    async def determine_javascript_quote_context(self, target, text):
        # Define and compile regex patterns for double and single quotes
        quote_patterns = {
            "double": re.compile(f'"[^"]*{target}[^"]*"'),
            "single": re.compile(f"'[^']*{target}[^']*'")
        }

        # Split the text by semicolons to isolate JavaScript statements
        statements = text.split(";")

        def is_balanced(section, target_index, quote_char):
            left = section[:target_index]
            right = section[target_index + len(target):]
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

        # If this came from paramminer_getparams and didn't have a http_reflection tag, we don't need to check again
        if (
            lightfuzz_event.type == "WEB_PARAMETER"
            and str(lightfuzz_event.module) == "paramminer_getparams"
            and "http-reflection" not in lightfuzz_event.tags
        ):
            self.lightfuzz.debug(
                "Got WEB_PARAMETER from paramminer, with no reflection tag - xss is not possible, aborting"
            )
            return

        reflection = None
        random_string = self.lightfuzz.helpers.rand_string(8)

        reflection_probe_result = await self.standard_probe(self.event.data["type"], cookies, random_string)
        if reflection_probe_result and random_string in reflection_probe_result.text:
            reflection = True

        if not reflection or reflection is False:
            return

        between_tags, in_tag_attribute, in_javascript = await self.determine_context(cookies, reflection_probe_result.text, random_string)
        self.lightfuzz.debug(
            f"determine_context returned: between_tags [{between_tags}], in_tag_attribute [{in_tag_attribute}], in_javascript [{in_javascript}]"
        )
        tags = ["z", "svg", "img"]
        if between_tags:
            for tag in tags:
                between_tags_probe = f"<{tag}>{random_string}</{tag}>"
                result = await self.check_probe(cookies, between_tags_probe, between_tags_probe, f"Between Tags ({tag} tag)")
                if result is True:
                    break

        if in_tag_attribute:
            in_tag_attribute_probe = f'{random_string}"'
            in_tag_attribute_match = f'"{random_string}""'
            await self.check_probe(cookies, in_tag_attribute_probe, in_tag_attribute_match, "Tag Attribute")


            in_tag_attribute_probe = f'javascript:{random_string}'
            in_tag_attribute_match = f'action="javascript:{random_string}'
            await self.check_probe(cookies, in_tag_attribute_probe, in_tag_attribute_match, "Form Action Injection")

        if in_javascript:
            in_javascript_probe = rf"</script><script>{random_string}</script>"
            result = await self.check_probe(cookies, in_javascript_probe, in_javascript_probe, "In Javascript")
            if result is False:
                quote_context = await self.determine_javascript_quote_context(random_string, reflection_probe_result.text)

                # Skip the test if the context is outside
                if quote_context == "outside":
                    return

                # Update probes based on the quote context
                if quote_context == "single":
                    in_javascript_escape_probe = rf"a\';zzzzz({random_string})\\"
                    in_javascript_escape_match = rf"a\\';zzzzz({random_string})\\"
                elif quote_context == "double":
                    in_javascript_escape_probe = rf'a\";zzzzz({random_string})\\'
                    in_javascript_escape_match = rf'a\\";zzzzz({random_string})\\'

                await self.check_probe(
                    cookies,
                    in_javascript_escape_probe,
                    in_javascript_escape_match,
                    f"In Javascript (escaping the escape character, {quote_context} quote)"
                )
