# /usr/bin/python

############################################################
#                                                          #
#                                                          #
#    [-] Processing BuiltWith Output                       #
#                                                          #
#    [-] 2022.08.19                                        #
#          V05                                             #
#          Black Lantern Security (BLSOPS)                 #
#                                                          #
#                                                          #
############################################################

import requests
from bbot.modules.base import BaseModule


class builtwithRedirects(BaseModule):

    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {"description": "Query Builtwith.com for subdomains", "auth_required": True}
    options = {"api_key": ""}
    options_desc = {"api_key": "Builtwith API key"}
    base_url = "https://api.builtwith.com"
    deps_pip = ["requests"]

    def setup(self):
        """
        Executes Setup.
        Calls ping() and verifies that the API is available
        If the API is not available the module DOES NOT execute

        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        super().setup()
        self.api_key = self.config.get("api_key", "")
        if self.api_key:
            try:
                status = self.ping()
                assert status == True
                self.hugesuccess(f"REDIRECTs API is ready")
                return status
            except Exception as e:
                return None, f"Error with REDIRECTs APIs"
        else:
            return None, "No API key set"

    def ping(self):
        """
        Verifies that each API is available

        Parameters
        ----------
        None

        Returns
        -------
        status (bool)
        """
        status = True
        try:
            r2 = self.helpers.request(
                f"{self.base_url}/redirect1/api.json?KEY={self.api_key}&LOOKUP=blacklanternsecurity.com"
            )
            resp2_content = getattr(r2, "text", "")
            assert getattr(r2, "status_code", 0) == 200, f"The REDIRECTs API is UNAVAILABLE"
        except AssertionError as iae:
            self.warning(iae)
            status = False
        return status

    def apiRedirectRequest(self, domain):
        """
        Calls the BuiltWith Domain API and converts JSON to python object

        Parameters
        ----------
        domain (string)

        Returns
        -------
        raw_data (dict)
        """
        raw_data = requests.get(
            "https://api.builtwith.com/redirect1/api.json?KEY=" + self.api_key + "&LOOKUP=" + domain
        ).json()

        return raw_data

    def extractRedirectsFromRaw(self, raw_data):
        """
        This function creates a list.
        Each entry in the list is either an Inbound or Outbound Redirect reported in the "Redirect Profile" page on builtwith.com

        Parameters
        ----------
        raw_data (dict): The python object that is created based on the JSON data from the API call.

        Returns
        -------
        redirectsRoster (list)
        """
        redirectsRoster = []  # Initialize final list
        try:
            assert raw_data != "Not found in DB", "No results returned from redirects query"
            for link_type in ["Outbound", "Inbound"]:
                try:
                    assert link_type in raw_data.keys(), f"No {link_type} links found in response"
                    links = raw_data.get(link_type, [])
                    assert type(links) is list, f"Non-list type returned for {link_type}: {type(links)}"
                    redirectsRoster += [link["Domain"] for link in links]
                except AssertionError as iae:
                    self.warning(iae)
        except AssertionError as ae:
            self.warning(ae)

        return redirectsRoster

    def handle_event(self, event):
        redirects = self.extractRedirectsFromRaw(self.apiRedirectRequest(event.data))
        for redirect in redirects:
            self.emit_event(redirect, "DNS_NAME", source=event)
