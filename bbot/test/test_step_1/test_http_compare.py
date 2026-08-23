"""
Tests for HTTP body comparison (``bbot.core.helpers.diff``).

``HttpCompare`` answers one question: is this response body the same as the
baseline, ignoring the parts observed to be volatile? These tests pin down that
contract and the cost of answering it.

  - ``TestLineBodyComparison``: HTML/text bodies, compared as lines.
  - ``TestXmlBodyComparison``: XML bodies, compared leaf-by-leaf by element path.
  - ``TestComparisonCost``: the comparison stays linear, and body parsing stays
    off the event loop. A body comparison holds the GIL for its whole duration,
    so a superlinear one stalls every module in the scan, not just its caller.
"""

import itertools
import json
import re
import time
from urllib.parse import urlparse

import pytest

from bbot.core.helpers.diff import MAX_STRUCTURED_BODY_SIZE, HttpCompare, _LineBody, _StructuredBody, parse_body
from bbot.test.mock_blasthttp import MockResponse

from ..bbot_fixtures import *  # noqa: F401, F403

NAV = [f'  <li class="nav n{i}"><a href="/section/{i}">Section {i}</a></li>' for i in range(60)]


def render(*, path="/x", token="tok", ts="1000", rows=20, echo_rows=10, promos=0, injected=None, rowsalt="a"):
    """A page whose volatile parts are a CSRF token, a timestamp, and the echoed request path."""
    lines = ["<!DOCTYPE html>", "<html lang=en>", "<head>", f'  <meta name="csrf" content="{token}">']
    lines += ["  <title>Acme</title>", "</head>", "<body>", f"  <!-- generated {ts} -->"]
    lines.append(f"  <p>No such page: <code>{path}</code></p>")
    if injected:
        lines.append(injected)
    lines += [f'  <div class="promo" data-slot="{j}">Promo {j}</div>' for j in range(promos)]
    lines += NAV
    lines += [f'  <li class="item i{i}"><span>{rowsalt} row {i}</span></li>' for i in range(rows)]
    lines += [f'  <a class="rel" href="{path}/rel/{i}">related {i}</a>' for i in range(echo_rows)]
    return "\n".join(lines + ["  <footer>&copy; Acme</footer>", "</body>", "</html>"])


def compare_bodies(baseline_1, baseline_2, subject):
    """Derive the volatile-content filter from two baseline samples, then compare a subject against it."""
    baseline_body, filters = HttpCompare._baseline_bodies(baseline_1, baseline_2)
    comparer = HttpCompare.__new__(HttpCompare)
    comparer.body_filters = filters
    return comparer.compare_body(baseline_body, parse_body(subject))


class TestLineBodyComparison:
    def test_html_parses_as_lines(self):
        # real-world HTML is not well-formed XML, so it lands on the line path
        assert isinstance(parse_body(render()), _LineBody)

    def test_volatile_content_is_ignored(self):
        """A catch-all host serving the same page with a new token/timestamp/path still matches."""
        baseline_1 = render(path="/aaaaaa/bbbb", token="t1", ts="100")
        baseline_2 = render(path="/cccccc/dddd", token="t2", ts="200")
        assert compare_bodies(baseline_1, baseline_2, render(path="/", token="t3", ts="300")) is True

    def test_identical_body_matches(self):
        body = render(path="/aaaaaa", token="t1", ts="100")
        assert compare_bodies(body, render(path="/cccccc", token="t2", ts="200"), body) is True

    @pytest.mark.parametrize(
        "subject_kwargs,description",
        [
            ({"injected": "  <div class=err>SQL syntax error near unexpected token</div>"}, "injected error line"),
            ({"injected": "  <pre>at com.acme.Handler(Handler.java:44)</pre>"}, "injected stack trace"),
            ({"rowsalt": "z"}, "different row content"),
            ({"rows": 40}, "extra rows"),
            ({"rows": 5}, "missing rows"),
            ({"promos": 4}, "extra block"),
        ],
    )
    def test_real_change_is_detected(self, subject_kwargs, description):
        """Volatile-content filtering must not swallow an actual change to the page."""
        baseline_1 = render(path="/aaaaaa/bbbb", token="t1", ts="100")
        baseline_2 = render(path="/cccccc/dddd", token="t2", ts="200")
        subject = render(path="/", token="t3", ts="300", **subject_kwargs)
        assert compare_bodies(baseline_1, baseline_2, subject) is False, f"failed to detect {description}"

    def test_stable_baseline_requires_exact_match(self):
        """With no volatile content, nothing is filtered, so a single added line is a difference."""
        baseline = render(path="/same", token="tok", ts="1")
        assert compare_bodies(baseline, baseline, baseline) is True
        subject = render(path="/same", token="tok", ts="1", injected="  <div>hello</div>")
        assert compare_bodies(baseline, baseline, subject) is False

    def test_comparison_is_order_insensitive(self):
        """Lines are matched by content, not position, so a reordered body still matches."""
        baseline = "\n".join(["<html>", "<a>", "<b>", "<c>", "</html>"])
        reordered = "\n".join(["<html>", "<c>", "<b>", "<a>", "</html>"])
        assert compare_bodies(baseline, baseline, reordered) is True

    def test_empty_bodies(self):
        assert compare_bodies("", "", "") is True
        assert compare_bodies("", "", "something") is False


class TestRawTextComparison:
    """``compare_body`` also takes raw response text, which is compared verbatim.

    lightfuzz's crypto submodule strips its own reflected probe values out of two
    responses and then compares what's left, so it needs an exact comparison and
    no volatile-content filtering. Raw text must not be treated as a sequence of
    characters, which would make anagrams compare equal.
    """

    @staticmethod
    def comparer(filters=None):
        comparer = HttpCompare.__new__(HttpCompare)
        comparer.body_filters = filters if filters is not None else set()
        return comparer

    def test_identical_text_matches(self):
        assert self.comparer().compare_body("invalid padding", "invalid padding") is True

    def test_differing_text_does_not_match(self):
        assert self.comparer().compare_body("invalid padding", "decryption failed") is False

    def test_anagrams_do_not_match(self):
        assert self.comparer().compare_body("abc", "cba") is False

    def test_single_character_difference_is_detected(self):
        """Padding-oracle detection turns on differences this small."""
        assert self.comparer().compare_body("result: 0x41", "result: 0x42") is False

    def test_filters_do_not_apply_to_raw_text(self):
        """A filter derived from a line-based baseline must not suppress a raw-text difference."""
        assert self.comparer(filters={0, 1, 2}).compare_body("invalid padding", "valid padding") is False


class TestXmlBodyComparison:
    @staticmethod
    def xml(*, token="tok", rows=20, changed=False):
        rows_xml = "".join(
            f"<row id='{i}'><name>{'CHANGED' if changed and i == 5 else f'item {i}'}</name><ref>static-{i}</ref></row>"
            for i in range(rows)
        )
        return f"<catalog><meta><token>{token}</token></meta>{rows_xml}</catalog>"

    def test_xml_parses_structurally(self):
        assert isinstance(parse_body(self.xml()), _StructuredBody)

    def test_volatile_leaf_is_ignored(self):
        assert compare_bodies(self.xml(token="a"), self.xml(token="b"), self.xml(token="c")) is True

    def test_real_element_change_is_detected(self):
        subject = self.xml(token="c", changed=True)
        assert compare_bodies(self.xml(token="a"), self.xml(token="b"), subject) is False

    def test_single_line_xml(self):
        """XML is keyed by element path, so it compares correctly with no line breaks to split on.

        A line-oriented comparison would see the whole document as one volatile
        line and consider every subsequent body a match.
        """
        assert "\n" not in self.xml()
        assert compare_bodies(self.xml(token="a"), self.xml(token="b"), self.xml(token="c")) is True
        assert compare_bodies(self.xml(token="a"), self.xml(token="b"), self.xml(token="c", changed=True)) is False

    def test_xml_versus_non_xml_is_a_difference(self):
        assert compare_bodies(self.xml(token="a"), self.xml(token="b"), render()) is False

    def test_samples_disagreeing_on_representation_fall_back_to_lines(self):
        """If only one sample parses as XML, both are compared as lines rather than by structure."""
        baseline_body, _ = HttpCompare._baseline_bodies(self.xml(), render())
        assert isinstance(baseline_body, _LineBody)


class TestJsonBodyComparison:
    """JSON APIs answer on a single line, so they need leaf-level comparison.

    Compared as lines, such a body is one line -- and if anything in it is
    volatile, that single line is filtered and every subsequent body matches,
    making the comparison useless for the modules that depend on it.
    """

    @staticmethod
    def api(*, token="tok", rows=6, changed=False, extra=None):
        body = {
            "meta": {"csrf": token, "page": 1},
            "results": [
                {"id": i, "name": "CHANGED" if changed and i == 3 else f"item {i}", "tags": ["a", "b"]}
                for i in range(rows)
            ],
        }
        if extra is not None:
            body["error"] = extra
        return json.dumps(body)

    def test_json_parses_structurally(self):
        assert isinstance(parse_body(self.api()), _StructuredBody)

    def test_json_is_served_on_one_line(self):
        assert "\n" not in self.api()

    def test_volatile_field_is_ignored(self):
        assert compare_bodies(self.api(token="a"), self.api(token="b"), self.api(token="c")) is True

    @pytest.mark.parametrize(
        "subject_kwargs,description",
        [
            ({"changed": True}, "changed value in a nested array"),
            ({"extra": "stack trace"}, "added top-level key"),
            ({"rows": 8}, "extra array elements"),
            ({"rows": 2}, "missing array elements"),
        ],
    )
    def test_real_change_is_detected(self, subject_kwargs, description):
        """The regression this guards: with a volatile field present, every one of
        these previously compared as a match, so nothing was ever detected."""
        subject = self.api(token="c", **subject_kwargs)
        assert compare_bodies(self.api(token="a"), self.api(token="b"), subject) is False, (
            f"failed to detect {description}"
        )

    def test_array_reordering_is_detected(self):
        """Leaves are keyed by path, so JSON array order is significant."""
        forward = json.dumps({"items": [1, 2, 3]})
        reversed_ = json.dumps({"items": [3, 2, 1]})
        assert compare_bodies(forward, forward, reversed_) is False

    def test_bare_scalar_is_compared_as_lines(self):
        """A scalar body flattens to a single leaf, which is no better than one line."""
        assert isinstance(parse_body("42"), _LineBody)
        assert isinstance(parse_body('"just a string"'), _LineBody)
        assert isinstance(parse_body("null"), _LineBody)

    def test_empty_containers_are_distinguished(self):
        assert compare_bodies('{"a": {}}', '{"a": {}}', '{"a": []}') is False
        assert compare_bodies('{"a": {}}', '{"a": {}}', '{"a": {"b": 1}}') is False

    def test_oversized_body_is_compared_as_lines(self):
        """Flattening is bounded so a huge body can't pin a big leaf map to the baseline."""
        oversized = json.dumps({"padding": "x" * MAX_STRUCTURED_BODY_SIZE})
        assert len(oversized) > MAX_STRUCTURED_BODY_SIZE
        assert isinstance(parse_body(oversized), _LineBody)

    def test_malformed_json_is_compared_as_lines(self):
        assert isinstance(parse_body('{"a": 1,,}'), _LineBody)
        assert isinstance(parse_body("{unterminated"), _LineBody)

    def test_deeply_nested_json_does_not_raise(self):
        """Untrusted bodies can be nested past the recursion limit; that must degrade, not crash."""
        nested = "[" * 5000 + "]" * 5000
        assert isinstance(parse_body(nested), _LineBody)


class TestBaselineIntegration:
    """End-to-end coverage of the real baseline-then-compare flow over HTTP.

    The comparisons above are driven directly. These go through ``_baseline()``
    and ``compare()``, so response parsing, the executor hop, header comparison
    and the diff-reason plumbing are all exercised together against a JSON API --
    the single-line body shape those modules see most often in practice.
    """

    @staticmethod
    def json_api(escalated_paths=()):
        """A JSON API with a volatile request id, served on a single line."""
        counter = itertools.count()

        def callback(request):
            path = urlparse(str(request.url)).path
            payload = {
                "request_id": f"req-{next(counter)}",
                "user": {"name": "alice", "role": "admin"},
                "items": [{"id": 1, "label": "one"}, {"id": 2, "label": "two"}],
            }
            if any(path.endswith(p) for p in escalated_paths):
                payload["user"]["role"] = "superuser"
            return MockResponse(status_code=200, text=json.dumps(payload))

        return callback

    @pytest.mark.asyncio
    async def test_json_api_filters_only_the_volatile_field(self, bbot_scanner, blasthttp_mock):
        scan = bbot_scanner()
        await scan._prep()
        blasthttp_mock.add_callback(callback=self.json_api(escalated_paths=("/escalated",)))

        comparer = scan.helpers.http_compare("http://jsonapi.example.com/api")
        await comparer._baseline()

        assert isinstance(comparer.baseline_body, _StructuredBody)
        # exactly one leaf is volatile -- not the whole body
        assert comparer.body_filters == {("request_id",)}

        match, reasons, _, _ = await comparer.compare("http://jsonapi.example.com/api")
        assert match is True, f"volatile request_id should have been filtered, got {reasons}"

        match, reasons, _, _ = await comparer.compare("http://jsonapi.example.com/api/escalated")
        assert match is False, "a changed nested field was not detected"
        assert "body" in reasons, f"expected a body difference, got {reasons}"

        await scan._cleanup()

    @pytest.mark.asyncio
    async def test_json_catchall_host_is_detected_as_wildcard(self, bbot_scanner, blasthttp_mock):
        """Wildcard detection reaches the comparison from the web helper, on any scan."""
        scan = bbot_scanner()
        await scan._prep()
        blasthttp_mock.add_callback(callback=self.json_api())

        result = await scan.helpers.web.is_http_wildcard_host("http", "catchall.example.com", 80)

        assert result not in (False, None), "JSON catch-all host was not detected as a wildcard responder"
        assert isinstance(result.baseline_body, _StructuredBody)

        await scan._cleanup()

    @pytest.mark.asyncio
    async def test_json_host_distinguishing_paths_is_not_a_wildcard(self, bbot_scanner, blasthttp_mock):
        """The root serves a different payload than the random probe paths, so this host is real."""
        scan = bbot_scanner()
        await scan._prep()
        blasthttp_mock.add_callback(callback=self.json_api(escalated_paths=("/",)))

        result = await scan.helpers.web.is_http_wildcard_host("http", "realsite.example.com", 80)

        assert result is False, f"host distinguishes responses by path but was reported as {result!r}"

        await scan._cleanup()


class TestComparisonCost:
    @staticmethod
    def echo_page(boilerplate_lines, echoed_lines, path):
        """A large catch-all page that echoes the request path into many otherwise-identical lines.

        This is the shape that stalls: the differing lines are numerous but each
        is nearly identical to its counterpart, which is the worst case for
        similarity-based diff pairing.
        """
        lines = ["<!DOCTYPE html>", "<html>", "<head>", "</head>", "<body>"]
        lines += [
            f'  <li class="nav n{i}"><a href="/section/{i}">Section {i}</a></li>' for i in range(boilerplate_lines)
        ]
        lines += [
            f'  <li class="rel r{i}"><a href="{path}/related/{i}">related item {i}</a></li>'
            for i in range(echoed_lines)
        ]
        return "\n".join(lines + ["</body>", "</html>"])

    def test_large_similar_bodies_compare_quickly(self):
        """An 8000-line catch-all page must not take minutes to compare.

        Similarity-based diff pairing is quadratic in the number of differing
        lines: this shape measured ~64s, and doubling it reached ~260s. The bound
        below is deliberately loose -- it is here to catch a return to
        superlinear cost, not to police small regressions.
        """
        baseline_1 = self.echo_page(6400, 1600, "/aaaaaaaaaaaa/bbbbbbbb")
        baseline_2 = self.echo_page(6400, 1600, "/cccccccccccc/dddddddd")
        subject = self.echo_page(6400, 1600, "/")

        started = time.monotonic()
        result = compare_bodies(baseline_1, baseline_2, subject)
        elapsed = time.monotonic() - started

        # same page, only the echoed path differs -- this host answers everything alike
        assert result is True
        assert elapsed < 10, f"comparison of an 8000-line body took {elapsed:.1f}s"

    def test_cost_scales_linearly(self):
        """Doubling the body must not quadruple the work."""

        def timed(boilerplate, echoed):
            pages = [self.echo_page(boilerplate, echoed, p) for p in ("/aaaaaaaa/bbbb", "/cccccccc/dddd", "/")]
            started = time.monotonic()
            compare_bodies(*pages)
            return time.monotonic() - started

        timed(400, 100)  # warm up, so import/allocation costs don't skew the ratio
        small = min(timed(1600, 400) for _ in range(3))
        large = min(timed(6400, 1600) for _ in range(3))

        # 4x the input. Linear would be ~4x; the quadratic behaviour was ~16x.
        assert large < small * 8, f"4x the body took {large / small:.1f}x the time ({small:.3f}s -> {large:.3f}s)"

    @pytest.mark.asyncio
    async def test_baseline_body_parsing_runs_off_the_event_loop(self, bbot_scanner, blasthttp_mock):
        """Parsing and diffing two full bodies is CPU-bound; it must not run on the event loop.

        A comparison holds the GIL for its whole duration, so doing it inline
        stalls every module in the scan.
        """
        scan = bbot_scanner()
        await scan._prep()
        blasthttp_mock.add_response(url=re.compile(r"http://cost\.example\.com.*"), text=render())

        executor_calls = []
        original = scan.helpers.run_in_executor_cpu

        def recording_executor(callback, *args, **kwargs):
            executor_calls.append(getattr(callback, "__name__", repr(callback)))
            return original(callback, *args, **kwargs)

        scan.helpers.run_in_executor_cpu = recording_executor

        comparer = scan.helpers.http_compare("http://cost.example.com")
        await comparer._baseline()

        assert "_baseline_bodies" in executor_calls, f"baseline parsing ran on the event loop: {executor_calls}"
        assert isinstance(comparer.baseline_body, _LineBody)

        await scan._cleanup()
