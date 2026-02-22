import re

from bbot.modules.base import BaseModule


class thc_lookup_base(BaseModule):
    ansi_escape_re = re.compile(r"\x1b\[[0-9;]*m")

    def _safe_json(self, response):
        if response is None:
            return {}
        if getattr(response, "status_code", 0) != 200:
            return {}
        try:
            data = response.json()
            if isinstance(data, dict):
                return data
        except Exception:
            pass
        return {}

    def _parse_legacy_page(self, text):
        results = set()
        next_url = ""
        for line in (text or "").splitlines():
            clean = self.ansi_escape_re.sub("", line).strip()
            if not clean:
                continue
            if clean.startswith(";;Next Page:"):
                next_url = clean.split(":", 1)[1].strip()
                continue
            if clean.startswith(";"):
                continue
            value = clean.rstrip(".")
            if value:
                results.add(value)
        return results, next_url
