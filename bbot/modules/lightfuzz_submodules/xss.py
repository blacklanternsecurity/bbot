from .base import BaseLightfuzz

import re


class XSSLightfuzz(BaseLightfuzz):
    def determine_context(self, html, random_string):
        between_tags = False
        in_tag_attribute = False
        in_javascript = False

        between_tags_regex = re.compile(rf"<(\/?\w+)[^>]*>.*?{random_string}.*?<\/?\w+>")
        in_tag_attribute_regex = re.compile(rf'<(\w+)\s+[^>]*?(\w+)="([^"]*?{random_string}[^"]*?)"[^>]*>')
        in_javascript_regex = re.compile(
            rf"<script\b[^>]*>(?:(?!<\/script>)[\s\S])*?{random_string}(?:(?!<\/script>)[\s\S])*?<\/script>"
        )

        between_tags_match = re.search(between_tags_regex, html)
        if between_tags_match:
            between_tags = True

        in_tag_attribute_match = re.search(in_tag_attribute_regex, html)
        if in_tag_attribute_match:
            in_tag_attribute = True

        in_javascript_regex = re.search(in_javascript_regex, html)
        if in_javascript_regex:
            in_javascript = True

        return between_tags, in_tag_attribute, in_javascript

    async def check_probe(self, probe, match, context):
        probe_result = await self.send_probe(probe)
        if probe_result and match in probe_result:
            self.results.append(
                {
                    "type": "FINDING",
                    "description": f"Possible Reflected XSS. Parameter: [{self.event.data['name']}] Context: [{context}]",
                }
            )
            return True
        return False

    async def fuzz(self):
        lightfuzz_event = self.event.parent

        # If this came from paramminer_getparams and didn't have a http_reflection tag, we don't need to check again
        if (
            lightfuzz_event.type == "WEB_PARAMETER"
            and lightfuzz_event.parent.type == "paramminer_getparams"
            and "http_reflection" not in lightfuzz_event.tags
        ):
            return

        reflection = None
        random_string = self.lightfuzz.helpers.rand_string(8)
        reflection_probe_result = await self.send_probe(random_string)
        if reflection_probe_result and random_string in reflection_probe_result:
            reflection = True

        if not reflection or reflection == False:
            return

        between_tags, in_tag_attribute, in_javascript = self.determine_context(reflection_probe_result, random_string)

        self.lightfuzz.debug(
            f"determine_context returned: between_tags [{between_tags}], in_tag_attribute [{in_tag_attribute}], in_javascript [{in_javascript}]"
        )
        tags = ["z","svg","img"]
        if between_tags:
            for tag in tags:
                between_tags_probe = f"<{tag}>{random_string}</{tag}>"
                result = await self.check_probe(between_tags_probe, between_tags_probe, f"Between Tags ({tag}) tag")
                if result == True:
                    continue

        if in_tag_attribute:
            in_tag_attribute_probe = f'{random_string}"'
            in_tag_attribute_match = f'"{random_string}""'
            await self.check_probe(in_tag_attribute_probe, in_tag_attribute_match, "Tag Attribute")

        if in_javascript:
            in_javascript_probe = rf"</script><script>{random_string}</script>"
            await self.check_probe(in_javascript_probe, in_javascript_probe, "In Javascript")
