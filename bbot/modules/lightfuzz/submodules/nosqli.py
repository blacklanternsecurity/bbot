from .base import BaseLightfuzz
from bbot.errors import HttpCompareError
import urllib.parse


class nosqli(BaseLightfuzz):
    """
    Detects NoSQL injection vulnerabilities.

    Techniques:

    * Quote Injection Analysis:
       - Injects single quotes and escaped single quotes into parameters
       - Compares response differences between the two to detect NoSQL parsing
       - Uses baseline comparison to validate findings and reduce false positives

    * Operator Injection:
       - Tests MongoDB-style operator injection using [$eq] and [$ne]
       - Modifies parameter names to include operators
       - Detects behavioral changes in application responses

    Validation of findings is achieved using confirmation probes to rule out unstable endpoints
    """

    friendly_name = "NoSQL Injection"

    async def fuzz(self):
        cookies = self.event.data.get("assigned_cookies", {})
        probe_value = self.incoming_probe_value(populate_empty=True)
        quote_probe_baseline = None
        try:
            quote_probe_baseline = self.compare_baseline(
                self.event.data["type"], probe_value, cookies, additional_params_populate_empty=True
            )
        except HttpCompareError as e:
            self.verbose(f"Encountered HttpCompareError Sending Compare Baseline: {e}")

        if quote_probe_baseline:
            try:
                # send the with a single quote, and then another with an escaped single quote
                (
                    single_quote_comparison,
                    single_quote_diff_reasons,
                    single_quote_reflection,
                    single_quote_response,
                ) = await self.compare_probe(
                    quote_probe_baseline,
                    self.event.data["type"],
                    f"{probe_value}'",
                    cookies,
                    additional_params_populate_empty=True,
                )
                (
                    escaped_single_quote_comparison,
                    escaped_single_quote_diff_reasons,
                    escaped_single_quote_reflection,
                    escaped_single_quote_response,
                ) = await self.compare_probe(
                    quote_probe_baseline,
                    self.event.data["type"],
                    rf"{probe_value}\'",
                    cookies,
                    additional_params_populate_empty=True,
                )
                if not single_quote_comparison and single_quote_response and escaped_single_quote_response:
                    # if the single quote probe changed the code or body, and the escaped single quote probe did not cause the same change, injection is possible
                    if ("code" in single_quote_diff_reasons or "body" in single_quote_diff_reasons) and (
                        single_quote_diff_reasons != escaped_single_quote_diff_reasons
                    ):
                        self.verbose(
                            "Initial heuristic indicates possible NoSQL Injection, sending confirmation probes"
                        )
                        confirm_baseline = self.compare_baseline(
                            self.event.data["type"],
                            urllib.parse.quote(f"{probe_value}' && 0 && 'x", safe=""),
                            cookies,
                            additional_params_populate_empty=True,
                            skip_urlencoding=True,
                        )
                        (
                            confirmation_probe_false_comparison,
                            confirmation_probe_false_diff_reasons,
                            confirmation_probe_false_reflection,
                            confirmation_probe_false_response,
                        ) = await self.compare_probe(
                            confirm_baseline,
                            self.event.data["type"],
                            urllib.parse.quote(f"{probe_value}' && 1 && 'x", safe=""),
                            cookies,
                            additional_params_populate_empty=True,
                            skip_urlencoding=True,
                        )
                        if confirmation_probe_false_response:
                            if not confirmation_probe_false_comparison and confirmation_probe_false_diff_reasons != [
                                "header"
                            ]:
                                (
                                    final_confirm_comparison,
                                    final_confirm_diff_reasons,
                                    final_confirm_reflection,
                                    final_confirm_response,
                                ) = await self.compare_probe(
                                    confirm_baseline,
                                    self.event.data["type"],
                                    urllib.parse.quote(f"{probe_value}' && 0 && 'x", safe=""),
                                    cookies,
                                    additional_params_populate_empty=True,
                                    skip_urlencoding=True,
                                )

                                if final_confirm_response and final_confirm_comparison:
                                    self.results.append(
                                        {
                                            "type": "FINDING",
                                            "description": f"Possible NoSQL Injection. {self.metadata()} Detection Method: [Quote/Escaped Quote + Conditional Affect] Differences: [{'.'.join(confirmation_probe_false_diff_reasons)}]",
                                        }
                                    )
                                else:
                                    self.verbose(
                                        "Aborted reporting Possible NoSQL Injection, due to unstable/inconsistent responses"
                                    )

            except HttpCompareError as e:
                self.verbose(f"Encountered HttpCompareError Sending Compare Probe: {e}")

        # Comparison operator injection
        if self.event.data["type"] in ["POSTPARAM", "GETPARAM"]:
            nosqli_negation_baseline = None

            try:
                nosqli_negation_baseline = self.compare_baseline(
                    self.event.data["type"],
                    f"{probe_value}'",
                    cookies,
                    additional_params_populate_empty=True,
                    parameter_name_suffix="[$eq]",
                    parameter_name_suffix_additional_params="[$eq]",
                )
            except HttpCompareError as e:
                self.verbose(f"Encountered HttpCompareError Sending Compare Baseline: {e}")

            if nosqli_negation_baseline:
                try:
                    (
                        nosqli_negate_comparison,
                        nosqli_negate_diff_reasons,
                        nosqli_negate_reflection,
                        nosqli_negate_response,
                    ) = await self.compare_probe(
                        nosqli_negation_baseline,
                        self.event.data["type"],
                        f"{probe_value}'",
                        cookies,
                        additional_params_populate_empty=True,
                        parameter_name_suffix="[$ne]",
                        parameter_name_suffix_additional_params="[$ne]",
                    )
                    if nosqli_negate_response:
                        if not nosqli_negate_comparison and nosqli_negate_diff_reasons != ["header"]:
                            # If we are about to report a finding, rule out a false positive from unstable URL by sending another probe with the baseline values, and ensure those dont also come back as different
                            (
                                nosqli_negate_comfirm_comparison,
                                nosqli_negate_confirm_diff_reasons,
                                nosqli_negate_confirm_reflection,
                                nosqli_negate_confirm_response,
                            ) = await self.compare_probe(
                                nosqli_negation_baseline,
                                self.event.data["type"],
                                f"{probe_value}'",
                                cookies,
                                additional_params_populate_empty=True,
                                parameter_name_suffix="[$eq]",
                                parameter_name_suffix_additional_params="[$eq]",
                            )
                            if nosqli_negate_comfirm_comparison:
                                self.results.append(
                                    {
                                        "type": "FINDING",
                                        "description": f"Possible NoSQL Injection. {self.metadata()} Detection Method: [Parameter Name Operator Injection - Negation ([$ne])] Differences: [{'.'.join(nosqli_negate_diff_reasons)}]",
                                    }
                                )
                except HttpCompareError as e:
                    self.verbose(f"Encountered HttpCompareError Sending Compare Probe: {e}")
