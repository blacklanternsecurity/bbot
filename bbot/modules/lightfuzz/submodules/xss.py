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

    # Attributes the browser will navigate to or fetch from. A `javascript:`
    # URL only becomes an XSS sink when reflected into one of these.
    _url_bearing_attrs = (
        "href",
        "src",
        "action",
        "formaction",
        "data",
        "poster",
        "background",
        "cite",
        "usemap",
        "icon",
        "manifest",
        "longdesc",
        "codebase",
        "ping",
        "archive",
        "xlink:href",
    )
    # Match `<attr>=` immediately at the end of a small preceding window.
    # Leading `[\s/]` requires a real attribute boundary so prefixes like
    # `data-href=` or `src-foo=` don't masquerade as URL-bearing.
    _url_attr_regex = re.compile(r"(?i)[\s/](" + "|".join(re.escape(a) for a in _url_bearing_attrs) + r")\s*=\s*$")

    async def determine_context(self, cookies, html, random_string):
        """
        Determines the context of the random string in the HTML response.
        With XSS, the context is what kind part of the page the injection is occuring in, which determine what payloads might be successful

        https://portswigger.net/web-security/cross-site-scripting/contexts

        Returns (between_tags, attribute_quote, in_javascript) where
        `attribute_quote` is '"' if the reflection is inside a double-quoted
        attribute, "'" if single-quoted, or None if the attribute context did
        not match. Tracking the quote character lets probes break out of the
        specific attribute wrapper rather than guessing and risking false
        positives from the wrong-quote character reflecting harmlessly inside.
        """
        between_tags = False
        attribute_quote = None
        in_javascript = False
        in_html_comment = False
        in_js_backtick = False

        between_tags_regex = re.compile(
            rf"<(\/?\w+)[^>]*>.*?{random_string}.*?<\/?\w+>"
        )  # The between tags context is when the injection occurs between HTML tags
        double_attr_regex = re.compile(
            rf'<(\w+)\s+[^>]*?(\w+)="([^"]*?{random_string}[^"]*?)"[^>]*>'
        )  # attribute context with double-quoted value
        single_attr_regex = re.compile(
            rf"<(\w+)\s+[^>]*?(\w+)='([^']*?{random_string}[^']*?)'[^>]*>"
        )  # attribute context with single-quoted value
        in_javascript_regex = re.compile(
            rf"<script\b[^>]*>[^<]*(?:<(?!\/script>)[^<]*)*{random_string}[^<]*(?:<(?!\/script>)[^<]*)*<\/script>"
        )  # The in javascript context is when the injection occurs within a <script> tag
        # HTML comment context: `<!-- ... {random} ... -->`. Breakout is
        # closing the comment with `-->` and injecting fresh markup.
        in_html_comment_regex = re.compile(rf"<!--(?:(?!-->).)*?{random_string}(?:(?!-->).)*?-->", re.DOTALL)
        # JS template literal (backtick) context: reflection inside a
        # `...${x}...` style string. Exploitable via `${}` interpolation.
        in_js_backtick_regex = re.compile(
            rf"<script\b[^>]*>[^<]*(?:<(?!\/script>)[^<]*)*`[^`]*{random_string}[^`]*`"
            rf"[^<]*(?:<(?!\/script>)[^<]*)*<\/script>"
        )

        between_tags_match = await self.lightfuzz.helpers.re.search(between_tags_regex, html)
        if between_tags_match:
            between_tags = True

        if await self.lightfuzz.helpers.re.search(double_attr_regex, html):
            attribute_quote = '"'
        elif await self.lightfuzz.helpers.re.search(single_attr_regex, html):
            attribute_quote = "'"

        in_javascript_match = await self.lightfuzz.helpers.re.search(in_javascript_regex, html)
        if in_javascript_match:
            in_javascript = True

        if await self.lightfuzz.helpers.re.search(in_html_comment_regex, html):
            in_html_comment = True

        if await self.lightfuzz.helpers.re.search(in_js_backtick_regex, html):
            in_js_backtick = True

        return between_tags, attribute_quote, in_javascript, in_html_comment, in_js_backtick

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

    def _verify_match_context(self, html, match, context):
        """Verify the match appears in the correct HTML context, not just anywhere in the response.
        When the same parameter is reflected in multiple contexts with different encoding,
        a match found in the wrong context can cause false positives."""
        if "Tag Attribute" in context:
            # Verify match is inside a tag (between < and >), not in text content
            pos = html.find(match)
            while pos != -1:
                preceding = html[:pos]
                last_open = preceding.rfind("<")
                last_close = preceding.rfind(">")
                if last_open > last_close:
                    return True
                pos = html.find(match, pos + 1)
            return False
        elif "Between Tags" in context:
            pos = html.find(match)
            while pos != -1:
                preceding = html[:pos]
                last_open = preceding.rfind("<")
                last_close = preceding.rfind(">")
                if last_close > last_open:
                    return True
                pos = html.find(match, pos + 1)
            return False
        elif "In Javascript" in context:
            in_js_regex = re.compile(
                rf"<script\b[^>]*>[^<]*(?:<(?!\/script>)[^<]*)*{re.escape(match)}"
                rf"[^<]*(?:<(?!\/script>)[^<]*)*<\/script>"
            )
            return bool(in_js_regex.search(html))
        elif "URL-scheme Injection" in context:
            # The match key starts with the wrapping quote (`"javascript:RAND`
            # or `'javascript:RAND`). The attribute name and `=` live in the
            # bytes immediately preceding that quote. Only fire if at least
            # one occurrence is in a URL-bearing attribute — otherwise a
            # `<input value="javascript:...">` reflection (HTML-encoded, no
            # exploitation path) would false-positive.
            pos = html.find(match)
            while pos != -1:
                preceding = html[max(0, pos - 64) : pos]
                if self._url_attr_regex.search(preceding):
                    return True
                pos = html.find(match, pos + 1)
            return False
        elif "HTML Comment" in context:
            # Match begins inside an unclosed `<!--` (the `-->` that closes
            # the comment is INSIDE the match itself — that's the breakout).
            # Rules out a reflection of the same bytes elsewhere on the page
            # that didn't actually break out of any comment.
            pos = html.find(match)
            while pos != -1:
                preceding = html[:pos]
                if preceding.rfind("<!--") > preceding.rfind("-->"):
                    return True
                pos = html.find(match, pos + 1)
            return False
        elif "JS Template Literal" in context:
            # Match must land inside a `<script>` block AND inside a
            # backtick-delimited span (odd # of backticks since the last
            # script open, plus a closing backtick after the match). All
            # scans are bounded to slices of `html`; no regex over the body.
            pos = html.find(match)
            while pos != -1:
                preceding = html[:pos]
                last_script_open = preceding.rfind("<script")
                last_script_close = preceding.rfind("</script>")
                if last_script_open > last_script_close:
                    script_prefix = preceding[last_script_open:]
                    if script_prefix.count("`") % 2 == 1 and "`" in html[pos + len(match) :]:
                        return True
                pos = html.find(match, pos + 1)
            return False
        return True

    async def check_probe(self, cookies, probe, match, context):
        # Send the defined probe and look for the expected match value in the response
        probe_result = await self.standard_probe(self.event.data["type"], cookies, probe)
        if not probe_result or match not in probe_result.text:
            return False

        if not self._verify_match_context(probe_result.text, match, context):
            self.debug(
                f"Probe match found in response but not in the expected context [{context}]. "
                f"Likely reflected in a different context with different encoding. Suppressing."
            )
            return False

        self.results.append(
            {
                "name": "Possible Reflected XSS",
                "severity": "MEDIUM",
                "confidence": "MEDIUM",
                "type": "FINDING",
                "description": f"Possible Reflected XSS. Parameter: [{self.event.data['name']}] Context: [{context}] Parameter Type: [{self.event.data['type']}]{self.conversion_note()}",
            }
        )
        return True

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

        between_tags, attribute_quote, in_javascript, in_html_comment, in_js_backtick = await self.determine_context(
            cookies, reflection_probe_result.text, random_string
        )
        self.debug(
            f"determine_context returned: between_tags [{between_tags}], attribute_quote [{attribute_quote}], "
            f"in_javascript [{in_javascript}], in_html_comment [{in_html_comment}], in_js_backtick [{in_js_backtick}]"
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

        if attribute_quote:
            q = attribute_quote
            # After reflection in the HTTP response, did the wrapping quote survive without url-encoding or other sanitization/escaping?
            in_tag_attribute_probe = f"{random_string}{q}z"
            in_tag_attribute_match = f"{random_string}{q}z"
            await self.check_probe(
                cookies, in_tag_attribute_probe, in_tag_attribute_match, f"Tag Attribute ({q} quoted)"
            )

            # Account for apps that auto-wrap the reflected value in its own
            # quote pair (e.g. framework helpers that re-quote), producing
            # `{q}{value}{q}{q}z` after our breakout.
            in_tag_attribute_probe = f"{random_string}{q}z"
            in_tag_attribute_match = f"{q}{random_string}{q}{q}z"
            await self.check_probe(
                cookies, in_tag_attribute_probe, in_tag_attribute_match, f"Tag Attribute autoquote ({q} quoted)"
            )

            # URL-scheme injection: did `javascript:` survive into any
            # URL-bearing attribute? The match key is just `{q}javascript:{random}`
            # (no attribute name) so it triggers on href, src, action,
            # formaction, data, poster, etc.
            in_tag_attribute_probe = f"javascript:{random_string}"
            in_tag_attribute_match = f"{q}javascript:{random_string}"
            await self.check_probe(
                cookies, in_tag_attribute_probe, in_tag_attribute_match, f"URL-scheme Injection ({q} quoted)"
            )

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

                # Only run the escape-the-escape probe for quoted-string
                # contexts. Backtick-wrapped (template-literal) context is
                # handled separately below.
                if quote_context in ("single", "double"):
                    if quote_context == "single":
                        in_javascript_escape_probe = rf"a\';zzzzz({random_string})\\"
                        in_javascript_escape_match = rf"a\\';zzzzz({random_string})\\"
                    else:
                        in_javascript_escape_probe = rf"a\";zzzzz({random_string})\\"
                        in_javascript_escape_match = rf'a\\";zzzzz({random_string})\\'

                    await self.check_probe(
                        cookies,
                        in_javascript_escape_probe,
                        in_javascript_escape_match,
                        f"In Javascript (escaping the escape character, {quote_context} quote)",
                    )

        if in_html_comment:
            # Breakout probe: if `-->` survives reflection inside an HTML
            # comment, the attacker can close the comment and inject fresh
            # markup. Match must be inside the HTML comment's bounds — or
            # we'd be reflecting somewhere else.
            html_comment_probe = f"{random_string}-->z"
            html_comment_match = f"{random_string}-->z"
            await self.check_probe(cookies, html_comment_probe, html_comment_match, "HTML Comment")

        if in_js_backtick:
            # Template-literal probe: inside `...{injection}...` inside a
            # script tag, `${...}` interpolation runs arbitrary JS. If
            # `${`, the canary, and `}` all survive reflection unescaped,
            # the injection can execute JS via template-literal interpolation.
            backtick_probe = f"${{{random_string}}}"
            backtick_match = f"${{{random_string}}}"
            await self.check_probe(cookies, backtick_probe, backtick_match, "JS Template Literal")
