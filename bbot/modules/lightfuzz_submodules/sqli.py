from .base import BaseLightfuzz
from bbot.errors import HttpCompareError

import urllib.parse
import statistics


class SQLiLightfuzz(BaseLightfuzz):
    expected_delay = 5

    def evaluate_delay(self, mean_baseline, measured_delay):
        margin = 1.5
        if (
            mean_baseline + self.expected_delay - margin
            <= measured_delay
            <= mean_baseline + self.expected_delay + margin
        ):
            return True
        # check for exactly twice the delay, in case the statement gets placed in the query twice
        elif (
            mean_baseline + (self.expected_delay * 2) - margin
            <= measured_delay
            <= mean_baseline + (self.expected_delay * 2) + margin
        ):
            return True
        else:
            return False

    async def fuzz(self):

        cookies = self.event.data.get("assigned_cookies", {})

        # custom probe_value generation
        if "original_value" in self.event.data and self.event.data["original_value"] is not None:
            probe_value = urllib.parse.quote(str(self.event.data["original_value"]), safe="")

        else:
            probe_value = self.lightfuzz.helpers.rand_string(8, numeric_only=True)

        http_compare = self.compare_baseline(
            self.event.data["type"], probe_value, cookies, additional_params_populate_empty=True
        )

        try:
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

            if "code" in single_quote[1] and (single_quote[3].status_code != double_single_quote[3].status_code):
                self.results.append(
                    {
                        "type": "FINDING",
                        "description": f"Possible SQL Injection. {self.metadata()} Detection Method: [Single Quote/Two Single Quote]",
                    }
                )
        except HttpCompareError as e:
            self.lightfuzz.warning(f"Encountered HttpCompareError Sending Compare Probe: {e}")

        standard_probe_strings = [
            f"'||pg_sleep({str(self.expected_delay)})--",  # postgres
            f"1' AND (SLEEP({str(self.expected_delay)})) AND '",  # mysql
            f"' AND (SELECT FROM DBMS_LOCK.SLEEP({str(self.expected_delay)})) AND '1'='1"  # oracle (not tested)
            f"; WAITFOR DELAY '00:00:{str(self.expected_delay)}'--",  # mssql (not tested)
        ]
        method = "GET"

        baseline_1 = await self.standard_probe(
            self.event.data["type"], cookies, probe_value, additional_params_populate_empty=True
        )
        baseline_2 = await self.standard_probe(
            self.event.data["type"], cookies, probe_value, additional_params_populate_empty=True
        )

        if baseline_1 and baseline_2:
            baseline_1_delay = baseline_1.elapsed.total_seconds()
            baseline_2_delay = baseline_2.elapsed.total_seconds()
            mean_baseline = statistics.mean([baseline_1_delay, baseline_2_delay])

            for p in standard_probe_strings:
                confirmations = 0
                for i in range(0, 3):
                    r = await self.standard_probe(
                        self.event.data["type"],
                        cookies,
                        f"{probe_value}{p}",
                        additional_params_populate_empty=True,
                        timeout=20,
                    )
                    if not r:
                        self.lightfuzz.debug("delay measure request failed")
                        break

                    d = r.elapsed.total_seconds()
                    self.lightfuzz.debug(f"measured delay: {str(d)}")
                    if self.evaluate_delay(mean_baseline, d):
                        confirmations += 1
                        self.lightfuzz.debug(
                            f"{self.event.data['url']}:{self.event.data['name']}:{self.event.data['type']} Increasing confirmations, now: {str(confirmations)} "
                        )
                    else:
                        break

                if confirmations == 3:
                    self.results.append(
                        {
                            "type": "FINDING",
                            "description": f"Possible Blind SQL Injection. {self.metadata()} Detection Method: [Delay Probe ({p})]",
                        }
                    )

        else:
            self.lightfuzz.debug("Could not get baseline for time-delay tests")
