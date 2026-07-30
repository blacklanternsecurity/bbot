from urllib.parse import quote

from .base import BaseLightfuzz
from bbot.errors import HttpCompareError


class sqli(BaseLightfuzz):
    """
    Detects SQL injection vulnerabilities.

    Techniques:

    * Error-based Detection:
       - Injects single quotes and observes error responses
       - Tests quote escape sequence variations
       - Matches against known SQL error patterns

    * Code-change Detection:
       - Compares the status code of a single-quote probe against a doubled-quote probe
       - Requires a positive boolean (TRUE/FALSE) content differential to confirm

    * Time-based Blind Detection:
       - Uses vendor-specific time delay payloads
       - Confirms delays with statistical analysis
       - Requires multiple confirmations to eliminate false positives
    """

    friendly_name = "SQL Injection"

    delay_low = 3
    delay_high = 8
    delay_margin = 1.5
    delay_scale_margin = 1.75
    delay_stage1_reps = 3
    delay_stage2_reps = 3

    sqli_error_strings = [
        "Unterminated string literal",
        "Failed to parse string literal",
        "error in your SQL syntax",
        "syntax error at or near",
        "Unknown column",
        "unterminated quoted string",
        "Unclosed quotation mark",
        "Incorrect syntax near",
        "SQL command not properly ended",
        "string not properly terminated",
    ]

    # TRUE/FALSE payload pairs used to confirm the value reaches a SQL query. Both halves of a
    # pair are the same length and differ by a single character, so a reflected payload can be
    # stripped cleanly and any surviving body difference comes from the query result set.
    BOOLEAN_PROBE_PAIRS = [
        ("' AND '1'='1", "' AND '1'='2"),
        (" AND 1=1", " AND 1=2"),
    ]

    DELAY_PROBE_TEMPLATES = [
        "'||pg_sleep({d})--",
        "' OR (SELECT TRUE FROM pg_sleep({d})) LIMIT 1-- -",
        "1' AND (SLEEP({d})) AND '",
        "' OR SLEEP({d}) IS NOT NULL LIMIT 1-- -",
        " OR SLEEP({d}) IS NOT NULL LIMIT 1-- -",
        "' AND (SELECT 1 FROM DUAL WHERE DBMS_LOCK.SLEEP({d})=0) AND '1'='1",
        "'; WAITFOR DELAY '00:00:{d:02d}'--",
        "; WAITFOR DELAY '00:00:{d:02d}'--",
    ]

    async def _confirm_code_change(self, probe_value, cookies, initial_status_codes, rounds=2):
        """Run additional confirmation rounds with fresh baselines to rule out transient server/CDN flaps.

        Each round creates a new HttpCompare (fresh baseline pair) and re-runs both probes.
        Returns True only if every round produces the same (baseline, sq, dq) status codes
        as the initial detection and the baseline status code is stable across all rounds.
        """
        for i in range(rounds):
            try:
                fresh_compare = self.compare_baseline(
                    self.event.data["type"],
                    probe_value,
                    cookies,
                    additional_params_populate_empty=True,
                    emit_http_response=False,
                )
                sq = await self.compare_probe(
                    fresh_compare,
                    self.event.data["type"],
                    f"{probe_value}'",
                    cookies,
                    additional_params_populate_empty=True,
                )
                dq = await self.compare_probe(
                    fresh_compare,
                    self.event.data["type"],
                    f"{probe_value}''",
                    cookies,
                    additional_params_populate_empty=True,
                )
            except HttpCompareError as e:
                self.debug(f"Confirmation round {i + 1} baseline unstable: {e}")
                return False

            if not sq[3] or not dq[3]:
                self.debug(f"Confirmation round {i + 1} failed to get responses")
                return False

            round_status_codes = (
                fresh_compare.baseline.status_code,
                sq[3].status_code,
                dq[3].status_code,
            )

            # Baseline must be stable across rounds
            if round_status_codes[0] != initial_status_codes[0]:
                self.debug(
                    f"Confirmation round {i + 1} baseline status code changed "
                    f"({initial_status_codes[0]} -> {round_status_codes[0]}), discarding as flappy"
                )
                return False

            if round_status_codes != initial_status_codes:
                self.debug(
                    f"Confirmation round {i + 1} status codes changed: "
                    f"expected {initial_status_codes}, got {round_status_codes}"
                )
                return False

            self.debug(f"Confirmation round {i + 1} passed: {round_status_codes}")

        return True

    @staticmethod
    def _strip_payload(text, payload):
        """Remove reflected copies of a payload from a response body, in raw and encoded form."""
        for variant in (payload, quote(payload), payload.replace(" ", "+")):
            text = text.replace(variant, "")
        return text

    async def _probe_body(self, http_compare, payload, cookies):
        """Send ``payload`` and return its parsed response body, reflections of the payload
        stripped, ready for ``http_compare.compare_body()``.

        Returns None when the probe fails, or when the response is 403/429 (WAF or rate limit,
        which tells us nothing about the query behind the parameter).
        """
        try:
            probe = await self.compare_probe(
                http_compare,
                self.event.data["type"],
                payload,
                cookies,
                additional_params_populate_empty=True,
            )
        except HttpCompareError as e:
            self.debug(f"Boolean probe [{payload}] failed: {e}")
            return None
        if not probe[3]:
            return None
        if probe[3].status_code in (403, 429):
            self.debug(f"Boolean probe [{payload}] returned {probe[3].status_code}, cannot confirm")
            return None
        return http_compare.parse_body(self._strip_payload(probe[3].text, payload))

    async def confirm_boolean_differential(self, http_compare, probe_value, cookies):
        """Require positive SQL-logic evidence before asserting injection from a status change.

        A bare status flip is not SQL: a WAF signature match, or an envelope whose structural
        validity changes when the payload is repacked, both produce one. Only a TRUE/FALSE pair
        that changes the response *content* shows the value is reaching a query.

        Returns the confirming ``(true_payload, false_payload)`` pair, or None.
        """
        for true_suffix, false_suffix in self.BOOLEAN_PROBE_PAIRS:
            true_payload = f"{probe_value}{true_suffix}"
            false_payload = f"{probe_value}{false_suffix}"

            true_body = await self._probe_body(http_compare, true_payload, cookies)
            if true_body is None:
                continue
            false_body = await self._probe_body(http_compare, false_payload, cookies)
            if false_body is None:
                continue

            if http_compare.compare_body(true_body, false_body) is not False:
                self.debug(f"No boolean differential for [{true_suffix}] / [{false_suffix}]")
                continue

            # A page that renders differently on every request produces a differential on its
            # own. Re-send the TRUE payload; the body must reproduce for the pair to mean anything.
            repeat_body = await self._probe_body(http_compare, true_payload, cookies)
            if repeat_body is None:
                continue
            if http_compare.compare_body(true_body, repeat_body) is False:
                self.debug("Response body is not deterministic, discarding boolean differential")
                continue

            self.verbose(f"Boolean differential confirmed for {self.event.url}: [{true_suffix}] vs [{false_suffix}]")
            return true_payload, false_payload
        return None

    async def is_quote_specific(self, http_compare, probe_value, cookies, status_codes):
        """Verify the status flip tracks the quote characters and not the payload's shape.

        Appending one vs. two benign characters mirrors the `'`/`''` pair in length while
        carrying no SQL meaning. If that benign pair reproduces the same status triplet, the
        flip tracks value length or envelope validity rather than quoting.
        """
        control_codes = []
        for suffix in ("a", "aa"):
            try:
                control = await self.compare_probe(
                    http_compare,
                    self.event.data["type"],
                    f"{probe_value}{suffix}",
                    cookies,
                    additional_params_populate_empty=True,
                )
            except HttpCompareError as e:
                self.debug(f"Quote-specificity control probe failed: {e}")
                return True
            if not control[3]:
                return True
            control_codes.append(control[3].status_code)

        if (status_codes[0], *control_codes) == status_codes:
            self.debug(
                f"Benign control pair reproduced the status triplet {status_codes}, the change is not quote-specific"
            )
            return False
        return True

    async def fuzz(self):
        cookies = self.event.data.get("assigned_cookies", {})
        probe_value = self.incoming_probe_value(populate_empty=True)
        http_compare = self.compare_baseline(
            self.event.data["type"], probe_value, cookies, additional_params_populate_empty=True
        )

        try:
            # send the with a single quote, and then another with two single quotes
            single_quote = await self.compare_probe(
                http_compare,
                self.event.data["type"],
                f"{probe_value}'",
                cookies,
                additional_params_populate_empty=True,
            )
            double_single_quote = await self.compare_probe(
                http_compare,
                self.event.data["type"],
                f"{probe_value}''",
                cookies,
                additional_params_populate_empty=True,
            )
            # if the single quote probe response is different from the baseline
            if single_quote[0] is False:
                # check for common SQL error strings in the response
                for sqli_error_string in self.sqli_error_strings:
                    if sqli_error_string.lower() in single_quote[3].text.lower():
                        self.results.append(
                            {
                                "name": "Possible SQL Injection",
                                "severity": "HIGH",
                                "confidence": "MEDIUM",
                                "description": f"Possible SQL Injection. {self.metadata()} Detection Method: [SQL Error Detection] Detected String: [{sqli_error_string}]",
                            }
                        )
                        break
            # if both probes were successful (and had a response)
            if single_quote[3] and double_single_quote[3]:
                # Ensure none of the status codes are "429"
                if (
                    single_quote[3].status_code != 429
                    and double_single_quote[3].status_code != 429
                    and http_compare.baseline.status_code != 429
                    and http_compare.baseline.status_code != 403  # Ensure the baseline status code is not 403
                ):  # prevent false positives from rate limiting
                    # if the code changed in the single quote probe, and the code is NOT the same between that and the double single quote probe, SQL injection is indicated
                    if "code" in single_quote[1] and (
                        single_quote[3].status_code != double_single_quote[3].status_code
                    ):
                        # A transition into 403 is access control (usually a WAF matching its managed
                        # SQLi signature on the bare quote), not a code change driven by the query.
                        if 403 in (single_quote[3].status_code, double_single_quote[3].status_code):
                            self.debug(
                                "Quote probe transitioned into 403 (access control/WAF), "
                                "suppressing SQL injection finding"
                            )
                        else:
                            # Confirmation loop: require 2 additional rounds with fresh baselines
                            # to confirm the status-code triplet is stable and not a transient CDN/server flap.
                            # TODO: apply this same confirmation pattern to other submodules that use compare_probe-based detection.
                            initial_status_codes = (
                                http_compare.baseline.status_code,
                                single_quote[3].status_code,
                                double_single_quote[3].status_code,
                            )
                            confirmed = await self._confirm_code_change(probe_value, cookies, initial_status_codes)
                            quote_specific = confirmed and await self.is_quote_specific(
                                http_compare, probe_value, cookies, initial_status_codes
                            )
                            boolean_pair = (
                                await self.confirm_boolean_differential(http_compare, probe_value, cookies)
                                if quote_specific
                                else None
                            )
                            if boolean_pair:
                                self.results.append(
                                    {
                                        "name": "Possible SQL Injection",
                                        "severity": "HIGH",
                                        "confidence": "MEDIUM",
                                        "description": f"Possible SQL Injection. {self.metadata()} Detection Method: [Single Quote/Two Single Quote, Code Change ({initial_status_codes[0]}->{initial_status_codes[1]}->{initial_status_codes[2]})] Boolean Confirmation: [{boolean_pair[0]}] vs [{boolean_pair[1]}]",
                                    }
                                )
                            elif confirmed and quote_specific:
                                self.verbose(
                                    f"Discarding code change {initial_status_codes} for {self.event.url}: "
                                    "no boolean differential, the value does not reach a query"
                                )
            else:
                self.debug("Failed to get responses for both single_quote and double_single_quote")
        except HttpCompareError as e:
            self.verbose(f"Encountered HttpCompareError Sending Compare Probe: {e}")

        baseline_1 = await self.standard_probe(
            self.event.data["type"], cookies, probe_value, additional_params_populate_empty=True
        )
        baseline_2 = await self.standard_probe(
            self.event.data["type"], cookies, probe_value, additional_params_populate_empty=True
        )

        if baseline_1 and baseline_2:
            baseline_1_delay = baseline_1.elapsed.total_seconds()
            baseline_2_delay = baseline_2.elapsed.total_seconds()
            base_floor = min(baseline_1_delay, baseline_2_delay)

            junk_value = f"{probe_value}{self.lightfuzz.helpers.rand_string(20, numeric_only=True)}"
            junk_response = await self.standard_probe(
                self.event.data["type"], cookies, junk_value, additional_params_populate_empty=True
            )
            if junk_response:
                junk_delta = junk_response.elapsed.total_seconds() - base_floor
                if any(abs(junk_delta - k * self.delay_low) <= self.delay_margin for k in (1, 2)):
                    self.debug("Junk control probe matched delay window, aborting time-based tests")
                    return

            for template in self.DELAY_PROBE_TEMPLATES:
                # Stage 1: fast gate at delay_low
                low_times = []
                stage1_failed = False
                for _ in range(self.delay_stage1_reps):
                    payload_low = template.format(d=self.delay_low)
                    r = await self.standard_probe(
                        self.event.data["type"],
                        cookies,
                        f"{probe_value}{payload_low}",
                        additional_params_populate_empty=True,
                        timeout=20,
                    )
                    if not r:
                        self.debug("Stage 1 delay probe request failed")
                        stage1_failed = True
                        break
                    if r.status_code == 403:
                        self.debug("Stage 1 probe returned 403, skipping template")
                        stage1_failed = True
                        break
                    low_times.append(r.elapsed.total_seconds())

                if stage1_failed or not low_times:
                    continue

                f_low = min(low_times)
                d_low = f_low - base_floor

                k = None
                for candidate_k in (1, 2):
                    if abs(d_low - candidate_k * self.delay_low) <= self.delay_margin:
                        k = candidate_k
                        break

                if k is None:
                    self.debug(f"Stage 1 rejected: d_low={d_low:.2f}s does not match delay_low={self.delay_low}s")
                    continue

                self.verbose(f"Stage 1 passed {self.event.url}: d_low={d_low:.2f}s, k={k}, proceeding to Stage 2")

                # Stage 2: scaling confirmation at delay_high
                high_times = []
                stage2_failed = False
                for _ in range(self.delay_stage2_reps):
                    payload_high = template.format(d=self.delay_high)
                    r = await self.standard_probe(
                        self.event.data["type"],
                        cookies,
                        f"{probe_value}{payload_high}",
                        additional_params_populate_empty=True,
                        timeout=30,
                    )
                    if not r:
                        self.debug("Stage 2 delay probe request failed")
                        stage2_failed = True
                        break
                    if r.status_code == 403:
                        self.debug("Stage 2 probe returned 403, skipping template")
                        stage2_failed = True
                        break
                    high_times.append(r.elapsed.total_seconds())

                if stage2_failed or not high_times:
                    continue

                f_high = min(high_times)
                d_high = f_high - base_floor

                absolute_ok = abs(d_high - k * self.delay_high) <= self.delay_margin
                scaling_ok = abs((f_high - f_low) - k * (self.delay_high - self.delay_low)) <= self.delay_scale_margin

                if absolute_ok and scaling_ok:
                    self.results.append(
                        {
                            "name": "Possible Blind SQL Injection",
                            "severity": "HIGH",
                            "confidence": "MEDIUM",
                            "description": (
                                f"Possible Blind SQL Injection. {self.metadata()} "
                                f"Detection Method: [Delay Probe "
                                f"(k={k}, {self.delay_low}s->{d_low:.1f}s, {self.delay_high}s->{d_high:.1f}s)] "
                                f"Payload: [{payload_high}]"
                            ),
                        }
                    )
                else:
                    self.verbose(
                        f"Stage 2 rejected {self.event.url}: d_high={d_high:.2f}s, "
                        f"absolute_ok={absolute_ok}, scaling_ok={scaling_ok}"
                    )

        else:
            self.debug("Could not get baseline for time-delay tests")
