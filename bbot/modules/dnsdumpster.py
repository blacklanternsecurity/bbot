import json

from bbot.modules.templates.subdomain_enum import subdomain_enum


class dnsdumpster(subdomain_enum):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {
        "description": "Query dnsdumpster for subdomains",
        "created_date": "2022-03-12",
        "author": "@TheTechromancer",
    }

    base_url = "https://dnsdumpster.com"

    async def setup(self):
        self.apikey_regex = self.helpers.re.compile(r'<form[^>]*data-form-id="mainform"[^>]*hx-headers=\'([^\']*)\'')
        return True

    async def query(self, domain):
        ret = []
        # first, get the JWT token from the main page
        res1 = await self.api_request(self.base_url)
        status_code = getattr(res1, "status_code", 0)
        if status_code not in [200]:
            self.verbose(f'Bad response code "{status_code}" from DNSDumpster')
            return ret

        # Extract JWT token from the form's hx-headers attribute using regex
        jwt_token = None
        try:
            # Look for the form with data-form-id="mainform" and extract hx-headers
            form_match = await self.helpers.re.search(self.apikey_regex, res1.text)
            if form_match:
                headers_json = form_match.group(1)
                headers_data = json.loads(headers_json)
                jwt_token = headers_data.get("Authorization")
        except (AttributeError, json.JSONDecodeError, KeyError):
            self.log.warning("Error obtaining JWT token")
            return ret

        # Abort if we didn't get the JWT token
        if not jwt_token:
            self.verbose("Error obtaining JWT token")
            self.errorState = True
            return ret
        else:
            self.debug("Successfully obtained JWT token")

        if self.scan.stopping:
            return ret

        # Query the API with the JWT token
        res2 = await self.api_request(
            "https://api.dnsdumpster.com/htmld/",
            method="POST",
            data={"target": str(domain).lower()},
            headers={
                "Authorization": jwt_token,
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": "https://dnsdumpster.com",
                "Referer": "https://dnsdumpster.com/",
                "HX-Request": "true",
                "HX-Target": "results",
                "HX-Current-URL": "https://dnsdumpster.com/",
            },
        )
        status_code = getattr(res2, "status_code", 0)
        if status_code not in [200]:
            self.verbose(f'Bad response code "{status_code}" from DNSDumpster API')
            return ret

        return await self.scan.extract_in_scope_hostnames(res2.text)
