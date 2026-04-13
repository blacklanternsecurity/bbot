from .base import BaseLightfuzz
from bbot.errors import HttpCompareError

import statistics


class sqli(BaseLightfuzz):
    """
    Detects SQL injection vulnerabilities.

    Techniques:

    * Error-based Detection:
       - Injects single quotes and observes error responses
       - Tests quote escape sequence variations
       - Matches against known SQL error patterns

    * Time-based Blind Detection:
       - Uses vendor-specific time delay payloads
       - Confirms delays with statistical analysis
       - Requires multiple confirmations to eliminate false positives
    """

    friendly_name = "SQL Injection"

    expected_delay = 5
    # These are common error strings that strongly indicate SQL injection
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

    def evaluate_delay(self, mean_baseline, measured_delay):
        """
        Evaluates if a measured delay falls within an expected range, indicating potential SQL injection.

        Parameters:
        - mean_baseline (float): The average baseline delay measured from non-injected requests.
        - measured_delay (float): The delay measured from a potentially injected request.

        Returns:
        - bool: True if the measured delay is within the expected range or exactly twice the expected delay, otherwise False.

        The function checks if the measured delay is within a margin of the expected delay or twice the expected delay,
        accounting for cases where the injected statement might be executed twice.
        """
        margin = 1.5
        if (
            mean_baseline + self.expected_delay - margin
            <= measured_delay
            <= mean_baseline + self.expected_delay + margin
        ):
            return True
        # check for exactly twice the delay, in case the statement gets placed in the query twice (a common occurrence)
        elif (
            mean_baseline + (self.expected_delay * 2) - margin
            <= measured_delay
            <= mean_baseline + (self.expected_delay * 2) + margin
        ):
            return True
        else:
            return False

    async def _confirm_code_change(self, probe_value, cookies, initial_status_codes, rounds=2):
        """Run additional confirmation rounds with fresh baselines to rule out transient server/CDN flaps.

        Each round creates a new HttpCompare (fresh baseline pair) and re-runs both probes.
        Returns True only if every round produces the same (baseline, sq, dq) status codes
        as the initial detection and the baseline status code is stable across all rounds.
        """
        for i in range(rounds):
            try:
                fresh_compare = self.compare_baseline(
                    self.event.data["type"], probe_value, cookies, additional_params_populate_empty=True
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
                        # Check if the status code change is due to a WAF, not SQL injection
                        is_waf = False
                        if single_quote[3].status_code == 403:
                            waf_matches = await self.lightfuzz.helpers.yara.match(
                                self.lightfuzz.waf_yara_rules, single_quote[3].text
                            )
                            if waf_matches:
                                self.debug(
                                    "Single quote probe returned 403 with WAF signature, "
                                    "suppressing SQL injection finding"
                                )
                                is_waf = True
                        if not is_waf:
                            # Confirmation loop: require 2 additional rounds with fresh baselines
                            # to confirm the status-code triplet is stable and not a transient CDN/server flap.
                            # TODO: apply this same confirmation pattern to other submodules that use compare_probe-based detection.
                            initial_status_codes = (
                                http_compare.baseline.status_code,
                                single_quote[3].status_code,
                                double_single_quote[3].status_code,
                            )
                            confirmed = await self._confirm_code_change(probe_value, cookies, initial_status_codes)
                            if confirmed:
                                self.results.append(
                                    {
                                        "name": "Possible SQL Injection",
                                        "severity": "HIGH",
                                        "confidence": "MEDIUM",
                                        "description": f"Possible SQL Injection. {self.metadata()} Detection Method: [Single Quote/Two Single Quote, Code Change ({initial_status_codes[0]}->{initial_status_codes[1]}->{initial_status_codes[2]})]",
                                    }
                                )
            else:
                self.debug("Failed to get responses for both single_quote and double_single_quote")
        except HttpCompareError as e:
            self.verbose(f"Encountered HttpCompareError Sending Compare Probe: {e}")

        # These are common SQL injection payloads for inducing an intentional delay across several different SQL database types
        standard_probe_strings = [
            f"'||pg_sleep({str(self.expected_delay)})--",  # postgres
            f"1' AND (SLEEP({str(self.expected_delay)})) AND '",  # mysql
            f"' AND (SELECT FROM DBMS_LOCK.SLEEP({str(self.expected_delay)})) AND '1'='1"  # oracle (not tested)
            f"; WAITFOR DELAY '00:00:{str(self.expected_delay)}'--",  # mssql (not tested)
        ]

        baseline_1 = await self.standard_probe(
            self.event.data["type"], cookies, probe_value, additional_params_populate_empty=True
        )
        baseline_2 = await self.standard_probe(
            self.event.data["type"], cookies, probe_value, additional_params_populate_empty=True
        )

        # get a baseline from two different probes. We will average them to establish a mean baseline
        if baseline_1 and baseline_2:
            baseline_1_delay = baseline_1.elapsed.total_seconds()
            baseline_2_delay = baseline_2.elapsed.total_seconds()
            mean_baseline = statistics.mean([baseline_1_delay, baseline_2_delay])

            for p in standard_probe_strings:
                confirmations = 0
                for i in range(0, 3):
                    # send the probe 3 times, and check if the delay is within the detection threshold
                    r = await self.standard_probe(
                        self.event.data["type"],
                        cookies,
                        f"{probe_value}{p}",
                        additional_params_populate_empty=True,
                        timeout=20,
                    )
                    if not r:
                        self.debug("delay measure request failed")
                        break

                    d = r.elapsed.total_seconds()
                    self.debug(f"measured delay: {str(d)}")
                    if self.evaluate_delay(
                        mean_baseline, d
                    ):  # decide if the delay is within the detection threshold and constitutes a successful sleep execution
                        confirmations += 1
                        self.debug(
                            f"{self.event.url}:{self.event.data['name']}:{self.event.data['type']} Increasing confirmations, now: {str(confirmations)} "
                        )
                    else:
                        break

                if confirmations == 3:
                    self.results.append(
                        {
                            "name": "Possible Blind SQL Injection",
                            "severity": "HIGH",
                            "confidence": "LOW",
                            "description": f"Possible Blind SQL Injection. {self.metadata()} Detection Method: [Delay Probe ({p})]",
                        }
                    )

        else:
            self.debug("Could not get baseline for time-delay tests")
