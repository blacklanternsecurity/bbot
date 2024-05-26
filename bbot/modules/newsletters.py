# Created a new module called 'newsletters' that will scrape the websites (or recursive websites,
# thanks to BBOT's sub-domain enumeration) looking for the presence of an 'email type' that also
# contains a 'placeholder'. The combination of these two HTML items usually signify the presence
# of an "Enter Your Email Here" type Newsletter Subscription service. This module could be used
# to find newsletters for a future email bombing attack.

from .base import BaseModule
import re

# Known Websites with Newsletters
# https://futureparty.com/
# https://www.marketingbrew.com/
# https://buffer.com/
# https://www.milkkarten.net/
# https://geekout.mattnavarra.com/


class newsletters(BaseModule):
    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["FINDING"]
    flags = ["active", "safe"]
    meta = {
        "description": "Searches for Newsletter Submission Entry Fields on Websites",
        "created_date": "2024-02-02",
        "author": "@stryker2k2",
    }

    # Parse through Website to find a Text Entry Box of 'type = email'
    # and ensure that there is placeholder text within it.
    def find_type(self, soup):
        email_type = soup.find(type="email")
        if email_type:
            regex = re.compile(r"placeholder")
            if regex.search(str(email_type)):
                return True
        return False

    async def handle_event(self, event):
        _event = event

        # Call find_type Function if Webpage return Status Code 200 && "body" is found in event.data
        # Ex: 'bbot -m httpx newsletters -t https://apf-api.eng.vn.cloud.tesla.com' returns
        #     Status Code 200 but does NOT have event.data["body"]
        if _event.data["status_code"] == 200:
            if "body" in _event.data:
                body = _event.data["body"]
                soup = self.helpers.beautifulsoup(body, "html.parser")
                if soup is False:
                    self.debug(f"BeautifulSoup returned False")
                    return
                result = self.find_type(soup)
                if result:
                    description = f"Found a Newsletter Submission Form that could be used for email bombing attacks"
                    data = {"host": str(_event.host), "description": description, "url": _event.data["url"]}
                    await self.emit_event(
                        data,
                        "FINDING",
                        _event,
                        context="{module} searched HTTP_RESPONSE and identified {event.type}: a Newsletter Submission Form that could be used for email bombing attacks",
                    )
