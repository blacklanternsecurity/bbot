import re
from hashlib import sha256
from urllib.parse import parse_qsl, urlsplit

from bbot.modules.base import BaseModule
from bbot.core.helpers.async_helpers import NamedLock

# <script> types the browser runs; any other type holds data
SCRIPT_TYPES = {
    "",
    "module",
    "text/javascript",
    "application/javascript",
    "text/ecmascript",
    "application/ecmascript",
    "application/x-javascript",
}

# JavaScript tokens, coarsely: enough to tell code from data, not to parse it
JS_TOKEN = re.compile(
    r"""
    (?P<space>\s+)
    | (?P<comment>//[^\n]*|/\*[\s\S]*?(?:\*/|$))
    | (?P<string>"(?:[^"\\\n]|\\[\s\S])*"|'(?:[^'\\\n]|\\[\s\S])*')
    | (?P<number>\.?\d[\w.]*)
    | (?P<word>(?:[^\W\d]|\$)[\w$]*)
    | (?P<slash>/)
    | (?P<open>[\[{])
    | (?P<close>[\]}])
    | (?P<paren>[()])
    | (?P<punct>[^\s\w$"'`/\[\]{}()]+)
    | (?P<other>[\s\S])
    """,
    re.VERBOSE,
)
JS_REGEX = re.compile(r"/(?![*/])(?:[^/\\\n\[]|\\.|\[(?:[^\]\\\n]|\\.)*\])+/[A-Za-z]*")
# a template literal's text, up to its end or its next ${
JS_TEMPLATE_TEXT = re.compile(r"(?:[^`\\$]|\\[\s\S]|\$(?!\{))*")
JS_LITERAL_WORDS = {"true", "false", "null", "undefined", "NaN", "Infinity"}
# words after which a / starts a regex rather than dividing
JS_REGEX_AFTER = {
    "return",
    "typeof",
    "case",
    "do",
    "else",
    "in",
    "of",
    "new",
    "delete",
    "void",
    "throw",
    "yield",
    "await",
}
# punctuation an array or object of plain values can hold, e.g. [-1, !0] or {a: 1}
JS_DATA_PUNCT = set(",:-!")
# string literals in code up to this long are kept, so pages reading different parameters or elements stay apart
MAX_KEPT_STRING = 24


def js_tokens(code):
    """
    The tokens of some JavaScript, as (kind, text), without whitespace or comments.

    Kinds: "literal" (number, regex, template text, true/false/null), "string", "word", "open", "close", "paren",
    "punct" and "other". Input that isn't valid JavaScript still tokenizes, just less meaningfully.
    """
    tokens = []
    # for each ${...} substitution in a template literal we're inside, the brace depth it opened at
    substitutions = []
    depth = 0
    pos = 0

    def template_text(start):
        # the template's text up to its end or next substitution, as one literal; returns where the code resumes
        end = JS_TEMPLATE_TEXT.match(code, start).end()
        tokens.append(("literal", "`"))
        if code.startswith("${", end):
            substitutions.append(depth)
            return end + 2
        return end + 1

    while pos < len(code):
        char = code[pos]
        if char == "`":
            pos = template_text(pos + 1)
            continue
        if char == "}" and substitutions and substitutions[-1] == depth:
            substitutions.pop()
            pos = template_text(pos + 1)
            continue
        match = JS_TOKEN.match(code, pos)
        kind, text = match.lastgroup, match.group()
        pos = match.end()
        if kind in ("space", "comment"):
            continue
        if kind == "slash":
            kind = "punct"
            previous = tokens[-1] if tokens else None
            if (
                previous is None
                or previous[0] in ("open", "punct", "other")
                or previous == ("paren", "(")
                or (previous[0] == "word" and previous[1] in JS_REGEX_AFTER)
            ):
                regex = JS_REGEX.match(code, match.start())
                if regex:
                    kind, text, pos = "literal", regex.group(), regex.end()
        elif kind == "number" or (kind == "word" and text in JS_LITERAL_WORDS):
            kind = "literal"
        elif text == "{":
            depth += 1
        elif text == "}":
            depth -= 1
        tokens.append((kind, text))
    return tokens


def normalize_code(code):
    """
    Some JavaScript with its data blanked out and its code kept.

    Literals become `_`, except short strings in code, and an array or object holding only literals becomes a single
    `_`, so a list of 14 hotels reads the same as a list of 20. What's left is the code's structure, which pages built
    from the same template share however their data differs.
    """
    tokens = js_tokens(code)
    out = []
    # for each open array or object: where it starts in `out`, and whether it holds only data so far
    brackets = []
    for i, (kind, text) in enumerate(tokens):
        if kind == "open":
            brackets.append([len(out), True])
            out.append(text)
            continue
        if kind == "close":
            if brackets:
                start, data_only = brackets.pop()
                if data_only:
                    del out[start:]
                    out.append("_")
                    continue
                if brackets:
                    brackets[-1][1] = False
            out.append(text)
            continue
        is_key = kind in ("word", "string") and i + 1 < len(tokens) and tokens[i + 1][1].startswith(":")
        is_data = kind in ("literal", "string") or is_key or (kind == "punct" and set(text) <= JS_DATA_PUNCT)
        if brackets and not is_data:
            brackets[-1][1] = False
        if kind == "literal" or (kind == "string" and len(text) > MAX_KEPT_STRING + 2):
            out.append("_")
        else:
            out.append(text)
    return " ".join(out)


def script_key(url):
    """A script's URL without its query values or fragment, which are often cache busters or per-page data."""
    parsed = urlsplit(url)
    names = [name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)]
    return parsed._replace(query="&".join(names), fragment="").geturl()


class browser_vulns(BaseModule):
    """
    A module that loads web pages in the scan's browser and reports the client-side vulnerabilities it finds in them.

    Pages running the same code are analyzed once: see `page_code()` and `analyze_once()`. Modules declare
    `browser_artifacts = ["dom", "network"]` themselves, since module preloading reads only the module's own file.
    """

    watched_events = ["URL"]
    produced_events = ["FINDING"]

    async def setup(self):
        # the result for each code fingerprint analyzed
        self.analyzed = {}
        self.analysis_lock = NamedLock()
        self.pages_seen = 0
        return True

    def _incoming_dedup_hash(self, event):
        # pages with the same body are the same page
        body_hash = event.data.get("hash", {}).get("body_sha256", "")
        if body_hash:
            return hash((event.host, body_hash)), f"body_sha256={body_hash}"
        return hash(event), ""

    async def filter_event(self, event):
        if "status-200" not in event.tags:
            return False, "it isn't a 200"
        return True

    async def page_code(self, event):
        """
        Load `event`'s page in the browser, and return (visit, scripts, fingerprint): the `BrowserVisit`, its
        `page_scripts()` and its `code_fingerprint()`. None if there's no page to analyze.
        """
        visit = await self.browser_visit(event)
        if visit is None or not visit.dom:
            return None
        if visit.response.conclusion[0] == "needs_browser":
            self.debug(f"Skipping {event.url}: the browser couldn't get past its challenge")
            return None
        scripts = self.page_scripts(visit)
        fingerprint = self.code_fingerprint(visit.dom, scripts)
        self.debug(f"Code fingerprint of {event.url}: {fingerprint}")
        return visit, scripts, fingerprint

    def page_scripts(self, visit):
        """The scripts the page loaded, as {url: code}."""
        scripts = {}
        for request in visit.network:
            response = request["response"]
            if request["resource_type"] == "script" and response is not None and response.text.strip():
                scripts.setdefault(request["url"], response.text)
        return scripts

    def code_fingerprint(self, dom, script_urls):
        """
        A hash of the code in a page: its inline scripts, event handler attributes and javascript: URLs, through
        `normalize_code()`, and the URLs of its scripts, through `script_key()`. Pages built from the same template
        share one, however their content differs.
        """
        code = []
        soup = self.helpers.beautifulsoup(dom, "html.parser")
        for tag in soup.find_all(True):
            if tag.name == "script" and not tag.get("src") and tag.get("type", "").strip().lower() in SCRIPT_TYPES:
                code.append(normalize_code(tag.get_text()))
            for name, value in tag.attrs.items():
                if isinstance(value, list):
                    value = " ".join(value)
                if name.lower().startswith("on") or value.strip().lower().startswith("javascript:"):
                    code.append(f"{name}={normalize_code(value)}")
        code += sorted({script_key(url) for url in script_urls})
        return sha256("\0".join(code).encode()).hexdigest()

    async def analyze_once(self, key, analyze):
        """
        Await `analyze()` for the first page with this `key` (a code fingerprint, or something including one), and
        hand its result to every later page with the same key. Returns (result, first), where `first` is False if
        the result is another page's. If `analyze()` raises, nothing is kept, so the next page tries again.
        """
        self.pages_seen += 1
        async with self.analysis_lock.lock(key):
            if key in self.analyzed:
                return self.analyzed[key], False
            result = await analyze()
            self.analyzed[key] = result
            return result, True

    async def report(self):
        if self.pages_seen:
            self.info(f"Analyzed {len(self.analyzed):,} distinct sets of page code across {self.pages_seen:,} pages")

    async def emit_finding(self, event, url, name, description, severity, confidence, context):
        await self.emit_event(
            {
                "name": name,
                "description": description,
                "host": str(event.host),
                "url": url,
                "severity": severity,
                "confidence": confidence,
            },
            "FINDING",
            event,
            context=context,
        )
