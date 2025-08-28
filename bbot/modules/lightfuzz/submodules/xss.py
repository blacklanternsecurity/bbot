from .base import BaseLightfuzz

import regex as re


class xss(BaseLightfuzz):
    """
    Detects Reflected Cross-Site Scripting vulnerabilities across multiple contexts and techniques

    * Context Detection:
       - Between HTML Tags: <tag>injection</tag>
       - Within Tag Attributes: <tag attribute="injection">
       - Inside JavaScript: <script>var x = 'injection'</script>

    * Context-Specific Testing:
       - Between Tags: Tests basic HTML injection and tag creation
       - Tag Attributes: Tests quote escaping and JavaScript event handlers
       - JavaScript Context: Tests string delimiter breaking and script tag termination
       - Handles both single and double quote contexts in JavaScript

    Can often detect through WAFs, since it does not attempt to construct an exploitation payload
    """

    friendly_name = "Cross-Site Scripting"

    async def determine_context(self, cookies, html, random_string):
        """
        Determines the context of the random string in the HTML response.
        With XSS, the context is what kind part of the page the injection is occuring in, which determine what payloads might be successful

        https://portswigger.net/web-security/cross-site-scripting/contexts
        """
        between_tags = False
        in_tag_attribute = False
        in_javascript = False

        between_tags_regex = re.compile(
            rf"<(\/?\w+)[^>]*>.*?{random_string}.*?<\/?\w+>"
        )  # The between tags context is when the injection occurs between HTML tags
        in_tag_attribute_regex = re.compile(
            rf'<(\w+)\s+[^>]*?(\w+)="([^"]*?{random_string}[^"]*?)"[^>]*>'
        )  # The in tag attribute context is when the injection occurs in an attribute of an HTML tag
        in_javascript_regex = re.compile(
            rf"<script\b[^>]*>[^<]*(?:<(?!\/script>)[^<]*)*{random_string}[^<]*(?:<(?!\/script>)[^<]*)*<\/script>"
        )  # The in javascript context is when the injection occurs within a <script> tag

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
        quote_patterns = {"double": re.compile(f'"[^"]*{target}[^"]*"'), "single": re.compile(f"'[^']*{target}[^']*'")}

        # Split the text by semicolons to isolate JavaScript statements
        statements = text.split(";")

        # This function checks if the target string is balanced within a JavaScript statement
        def is_balanced(section, target_index, quote_char):
            left = section[:target_index]
            right = section[target_index + len(target) :]
            return left.count(quote_char) % 2 == 0 and right.count(quote_char) % 2 == 0

        # For each javascript statement, attempt to determine the type of quote we are within, and therefore what will enable breaking out of it to result in a successful XSS
        for statement in statements:
            for quote_type, pattern in quote_patterns.items():
                match = await self.lightfuzz.helpers.re.search(pattern, statement)
                if match:
                    context = match.group(0)
                    target_index = context.find(target)
                    opposite_quote = "'" if quote_type == "double" else '"'
                    if is_balanced(context, target_index, opposite_quote):
                        return quote_type
        # If we have no matches, the target string is most likely not within quotes
        return "outside"

    async def check_probe(self, cookies, probe, match, context):
        # Send the defined probe and look for the expected match value in the response
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
            self.debug("Got WEB_PARAMETER from paramminer, with no reflection tag - xss is not possible, aborting")
            return

        reflection = None
        random_string = self.lightfuzz.helpers.rand_string(8)

        reflection_probe_result = await self.standard_probe(self.event.data["type"], cookies, random_string)
        # before continuing, check if the random string is reflected in the response - a prerequisite for XSS
        if reflection_probe_result and random_string in reflection_probe_result.text:
            reflection = True

        if not reflection or reflection is False:
            return

        between_tags, in_tag_attribute, in_javascript = await self.determine_context(
            cookies, reflection_probe_result.text, random_string
        )
        self.debug(
            f"determine_context returned: between_tags [{between_tags}], in_tag_attribute [{in_tag_attribute}], in_javascript [{in_javascript}]"
        )
        tags = [
            "z",
            "svg",
            "img",
        ]  # These represent easy to exploit tags, along with an arbitrary tag which is less likely to be blocked
        if between_tags:
            for tag in tags:
                between_tags_probe = f"<{tag}>{random_string}</{tag}>"
                result = await self.check_probe(
                    cookies, between_tags_probe, between_tags_probe, f"Between Tags ({tag} tag)"
                )  # After reflection in the HTTP response, did the tags survive without url-encoding or other sanitization/escaping?
                if result is True:
                    break

        if in_tag_attribute:
            in_tag_attribute_probe = f'{random_string}"z'
            in_tag_attribute_match = f'{random_string}"z'
            await self.check_probe(
                cookies, in_tag_attribute_probe, in_tag_attribute_match, "Tag Attribute"
            )  # After reflection in the HTTP response, did the quote survive without url-encoding or other sanitization/escaping?

            in_tag_attribute_probe = f'{random_string}"z'
            in_tag_attribute_match = f'"{random_string}""z'
            await self.check_probe(
                cookies, in_tag_attribute_probe, in_tag_attribute_match, "Tag Attribute (autoquote)"
            )  # After reflection in the HTTP response, did the quote survive without url-encoding or other sanitization/escaping (and account for auto-quoting)

            in_tag_attribute_probe = f"javascript:{random_string}"
            in_tag_attribute_match = f'action="javascript:{random_string}'
            await self.check_probe(
                cookies, in_tag_attribute_probe, in_tag_attribute_match, "Form Action Injection"
            )  # After reflection in the HTTP response, did the javascript sch

        if in_javascript:
            in_javascript_probe = rf"</script><script>{random_string}</script>"
            result = await self.check_probe(
                cookies, in_javascript_probe, in_javascript_probe, "In Javascript"
            )  # After reflection in the HTTP response, did the script tags survive without url-encoding or other sanitization/escaping?
            if result is False:
                # To attempt this technique, we need to determine the type of quote we are within
                quote_context = await self.determine_javascript_quote_context(
                    random_string, reflection_probe_result.text
                )

                # Skip the test if the context is outside
                if quote_context == "outside":
                    return

                # Update probes based on the quote context
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
