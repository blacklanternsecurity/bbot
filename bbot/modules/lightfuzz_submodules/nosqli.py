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
        http_compare = self.compare_baseline(
            self.event.data["type"], probe_value, cookies, additional_params_populate_empty=True
        )

        try:
            # send the with a single quote, and then another with an escaped single quote
            (
                single_quote_comparison,
                single_quote_diff_reasons,
                single_quote_reflection,
                single_quote_response,
            ) = await self.compare_probe(
                http_compare,
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
                http_compare,
                self.event.data["type"],
                rf"{probe_value}\'",
                cookies,
                additional_params_populate_empty=True,
            )
            # if both probes were successful (and had a response)
            if single_quote_response and escaped_single_quote_response:
                # if the single quote probe changed the code or body, and the escaped single quote probe did not cause the same change, injection is possible
                if ("code" in single_quote_diff_reasons or "body" in single_quote_diff_reasons) and (
                    single_quote_diff_reasons != escaped_single_quote_diff_reasons
                ):
                    self.lightfuzz.critical(
                        "Initial heuristic indicates possible NoSQL Injection, sending confirmation probes"
                    )
                    (
                        confirmation_probe_true_comparson,
                        confirmation_probe_true_diff_reasons,
                        confirmation_probe_true_reflection,
                        confirmation_probe_true_response,
                    ) = await self.compare_probe(
                        http_compare,
                        self.event.data["type"],
                        urllib.parse.quote(f"{probe_value}' && 0 && 'x", safe=""),
                        cookies,
                        additional_params_populate_empty=True,
                        skip_urlencoding=True,
                    )
                    (
                        confirmation_probe_false_comparson,
                        confirmation_probe_false_diff_reasons,
                        confirmation_probe_false_reflection,
                        confirmation_probe_false_response,
                    ) = await self.compare_probe(
                        http_compare,
                        self.event.data["type"],
                        urllib.parse.quote(f"{probe_value}' && 1 && 'x", safe=""),
                        cookies,
                        additional_params_populate_empty=True,
                        skip_urlencoding=True,
                    )
                    if confirmation_probe_true_response and confirmation_probe_false_response:
                        self.lightfuzz.hugewarning(confirmation_probe_false_response.text.lower())
                        self.lightfuzz.hugewarning(confirmation_probe_true_response.text.lower())
                        self.lightfuzz.hugeinfo(
                            confirmation_probe_true_response.text.lower()
                            == confirmation_probe_false_response.text.lower()
                        )
                        if (
                            confirmation_probe_false_response.status_code
                            != confirmation_probe_true_response.status_code
                        ) or (
                            confirmation_probe_false_response.text.lower()
                            != confirmation_probe_true_response.text.lower()
                        ):
                            self.results.append(
                                {
                                    "type": "FINDING",
                                    "description": f"Possible NoSQL Injection. {self.metadata()} Detection Method: [Quote/Escaped Quote + Conditional Affect]",
                                }
                            )
            else:
                self.lightfuzz.debug("Failed to get responses for both single_quote and double_single_quote")
        except HttpCompareError as e:
            self.lightfuzz.warning(f"Encountered HttpCompareError Sending Compare Probe: {e}")
