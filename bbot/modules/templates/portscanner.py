from bbot.modules.base import BaseModule


class portscanner(BaseModule):
    """
    A portscanner containing useful methods for nmap, masscan, etc.
    """

    async def setup(self):
        self.ip_ranges = [e.host for e in self.scan.target.events if e.type == "IP_RANGE"]
        exclude, invalid_exclude = self._build_targets(self.scan.blacklist)
        self.exclude_file = None
        if exclude:
            self.exclude_file = self.helpers.tempfile(exclude, pipe=False)
        if invalid_exclude > 0:
            self.warning(
                f"Port scanner can only accept IP addresses or IP ranges as blacklist ({invalid_exclude:,} blacklisted were hostnames)"
            )
        return True

    async def filter_event(self, event):
        # skip IP_ADDRESSes if they are included in any of our target IP_RANGEs
        if event.type == "IP_ADDRESS":
            for net in self.helpers.ip_network_parents(event.data, include_self=True):
                if net in self.ip_ranges:
                    return False, f"Skipping {event.host} because it is already included in {net}"
        return True

    def _build_targets(self, target, delimiter=","):
        invalid_targets = 0
        targets = []
        for t in target:
            t = self.helpers.make_ip_type(t.data)
            if isinstance(t, str):
                invalid_targets += 1
            else:
                if self.helpers.is_ip(t):
                    targets.append(f"{t}/32")
                else:
                    targets.append(str(t))
        return targets, invalid_targets
