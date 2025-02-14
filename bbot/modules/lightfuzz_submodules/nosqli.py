from .base import BaseLightfuzz
from bbot.errors import HttpCompareError
import urllib.parse


class NoSQLiLightfuzz(BaseLightfuzz):
    """
    NoSQLi Lightfuzz module
    """

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
                if single_quote_response and escaped_single_quote_response:
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
                                self.results.append(
                                    {
                                        "type": "FINDING",
                                        "description": f"Possible NoSQL Injection. {self.metadata()} Detection Method: [Quote/Escaped Quote + Conditional Affect]",
                                    }
                                )

            except HttpCompareError as e:
                self.verbose(f"Encountered HttpCompareError Sending Compare Probe: {e}")

            else:
                # if both probes were successful (and had a response)

                self.verbose("Failed to get responses for both single_quote and double_single_quote")

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
                            self.results.append(
                                {
                                    "type": "FINDING",
                                    "description": f"Possible NoSQL Injection. {self.metadata()} Detection Method: [Parameter Name Operator Injection - Negation ([$ne])] Differences: [{'.'.join(nosqli_negate_diff_reasons)}]",
                                }
                            )
                except HttpCompareError as e:
                    self.verbose(f"Encountered HttpCompareError Sending Compare Probe: {e}")
