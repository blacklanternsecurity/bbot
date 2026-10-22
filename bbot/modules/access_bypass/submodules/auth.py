from bbot.errors import HttpCompareError

from .base import BaseAccessBypass, is_allowed_status

# AWS API Gateway custom-authorizer blueprint sentinels; "deny" returns a single-resource
# Deny policy that the gateway caches by token value, authorizing every other resource.
apigw_sentinels = ["deny", "unauthorized", "allow"]


class auth(BaseAccessBypass):
    friendly_name = "Authentication Bypass"
    severity = "HIGH"

    def applies(self):
        # Bearer-prefix check is 401-only; API Gateway check is gated on the baseline headers
        return self.event.http_status in (401, 403)

    async def run(self):
        baseline = await self.compare_helper.get_baseline()
        if self.is_api_gateway(baseline):
            await self.run_apigw(baseline)
        elif self.event.http_status == 401:
            await self.run_bearer()

    @staticmethod
    def is_api_gateway(response):
        return any(h.lower() in ("x-amzn-requestid", "x-amzn-errortype") for h in response.headers.keys())

    async def run_bearer(self):
        token = self.helpers.rand_string(8)
        try:
            match, reasons, _, response = await self.compare_helper.compare(
                self.event.url, headers={"Authorization": f"Bearer {token}"}, allow_redirects=self.follow_redirects
            )
        except HttpCompareError as e:
            self.access_bypass.debug(e)
            return
        if await self.is_bypass_from_match(match, response):
            self.add_result(
                f"{self.friendly_name}: [{','.join(reasons)}] Sig: [Added Header: Authorization: Bearer <garbage>]",
                confidence="MEDIUM",
            )

    async def is_bypass_from_match(self, match, response):
        if match is not False or response is None or not is_allowed_status(response.status_code):
            return False
        return not await self.access_bypass.is_waf_response(response)

    async def run_apigw(self, baseline):
        for sentinel in apigw_sentinels:
            response = await self.helpers.request(
                self.event.url, headers={"Authorization": sentinel}, follow_redirects=False
            )
            if response is None:
                continue
            if self.is_apigw_bypass(response):
                self.add_result(
                    f"{self.friendly_name}: API Gateway authorizer bypass via 'Authorization: {sentinel}' "
                    f"(backend reached, x-amzn-remapped-* headers present)",
                    severity="HIGH",
                    confidence="HIGH",
                )
                return
            # a cached Deny policy means the sentinel authorizes OTHER resources; probe the host root once
            if response.headers.get("x-amzn-errortype", "").startswith("AccessDenied"):
                await self.probe_apigw_root(sentinel)

    async def probe_apigw_root(self, sentinel):
        root = f"{self.base_url}/"
        if root == self.event.url:
            return
        response = await self.helpers.request(root, headers={"Authorization": sentinel}, follow_redirects=False)
        if response is not None and self.is_apigw_bypass(response):
            self.add_result(
                f"{self.friendly_name}: API Gateway authorizer bypass via cached Deny policy "
                f"('Authorization: {sentinel}'); {root} reached the backend",
                severity="HIGH",
                confidence="HIGH",
                url=root,
            )

    @staticmethod
    def is_apigw_bypass(response):
        if not is_allowed_status(response.status_code):
            return False
        return any(h.lower().startswith("x-amzn-remapped-") for h in response.headers.keys())
