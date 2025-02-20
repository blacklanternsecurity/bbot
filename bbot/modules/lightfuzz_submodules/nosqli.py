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
        try:
            quote_probe_baseline = self.compare_baseline(
                self.event.data["type"], probe_value, cookies, additional_params_populate_empty=True
            )
        except HttpCompareError as e:
            self.verbose(f"Encountered HttpCompareError Sending Compare Baseline: {e}")
            quote_probe_baseline = None

        if quote_probe_baseline:
            await self.run_quote_injection_tests(quote_probe_baseline, probe_value, cookies)

        if self.event.data["type"] in ["POSTPARAM", "GETPARAM"]:
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
                nosqli_negation_baseline = None

            if nosqli_negation_baseline:
                await self.run_comparison_operator_injection_tests(nosqli_negation_baseline, probe_value, cookies)

    async def run_quote_injection_tests(self, quote_probe_baseline, probe_value, cookies):
        try:
            single_quote_comparison, single_quote_diff_reasons, _, single_quote_response = await self.compare_probe(
                quote_probe_baseline,
                self.event.data["type"],
                f"{probe_value}'",
                cookies,
                additional_params_populate_empty=True,
            )
            (
                escaped_single_quote_comparison,
                escaped_single_quote_diff_reasons,
                _,
                escaped_single_quote_response,
            ) = await self.compare_probe(
                quote_probe_baseline,
                self.event.data["type"],
                rf"{probe_value}\'",
                cookies,
                additional_params_populate_empty=True,
            )

            if (
                not single_quote_comparison
                and single_quote_response
                and escaped_single_quote_response
                and ("code" in single_quote_diff_reasons or "body" in single_quote_diff_reasons)
                and single_quote_diff_reasons != escaped_single_quote_diff_reasons
            ):
                self.verbose("Initial heuristic indicates possible NoSQL Injection, sending confirmation probes")

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
                    _,
                    confirmation_probe_false_response,
                ) = await self.compare_probe(
                    confirm_baseline,
                    self.event.data["type"],
                    urllib.parse.quote(f"{probe_value}' && 1 && 'x", safe=""),
                    cookies,
                    additional_params_populate_empty=True,
                    skip_urlencoding=True,
                )

                if (
                    confirmation_probe_false_response
                    and not confirmation_probe_false_comparison
                    and confirmation_probe_false_diff_reasons != ["header"]
                ):
                    final_confirm_comparison, _, _, final_confirm_response = await self.compare_probe(
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

    async def run_comparison_operator_injection_tests(self, nosqli_negation_baseline, probe_value, cookies):
        try:
            nosqli_negate_comparison, nosqli_negate_diff_reasons, _, nosqli_negate_response = await self.compare_probe(
                nosqli_negation_baseline,
                self.event.data["type"],
                f"{probe_value}'",
                cookies,
                additional_params_populate_empty=True,
                parameter_name_suffix="[$ne]",
                parameter_name_suffix_additional_params="[$ne]",
            )

            if nosqli_negate_response and not nosqli_negate_comparison and nosqli_negate_diff_reasons != ["header"]:
                nosqli_negate_comfirm_comparison, _, _, nosqli_negate_confirm_response = await self.compare_probe(
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
