# /usr/bin/python

############################################################
#                                                          #
#                                                          #
#    [-] Processing BuiltWith Domains Output               #
#                                                          #
#    [-] 2022.08.19                                        #
#          V05                                             #
#          Black Lantern Security (BLSOPS)                 #
#                                                          #
#                                                          #
############################################################

import requests
from bbot.modules.base import BaseModule

class builtwithDomains(BaseModule):

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
                status=self.ping()
                assert status==True
                self.hugesuccess(f"Domains API is ready")
                return status
            except Exception as e:
                return None,f"Error with API"
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
        status=True
        try:
            r = self.helpers.request(f"{self.base_url}/v20/api.json?KEY={self.api_key}&LOOKUP=blacklanternsecurity.com")
            resp_content = getattr(r, "text", "")
            assert getattr(r, "status_code", 0) == 200, f"The DOMAINS API is UNAVAILABLE"
        except AssertionError as iae:
            self.warning(iae)
            status=False
        return status

    def apiTechnologyRequest(self, domain):
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
            "https://api.builtwith.com/v20/api.json?KEY=" + self.api_key + "&LOOKUP=" + domain
        ).json()

        return raw_data

    def extractSubdomainsFromRaw(self, raw_data):
        """
        This function creates a list.
        Each entry in the list is an "FQDN" that was reported in the "Detailed Technology Profile" page on builtwith.com

        Parameters
        ----------
        raw_data (dict): The python object that is created based on the JSON data from the API call.

        Returns
        -------
        domainRoster (list)
        """
        domainRoster = []  # Initialize final list
        try:
            assert len(raw_data.get("Errors", [])) == 0, (raw_data.get("Errors",[]))[0]["Message"]
            assert len(raw_data.get("Results", [])) > 0, "No results returned from BUILTWITH query"
            
            for chunk in raw_data["Results"][0]["Result"]["Paths"]: # Extract subdomains from results
                if chunk["SubDomain"]:
                    fqdn = str(chunk["SubDomain"]) + "." + str(chunk["Domain"])
                else:
                    fqdn = str(chunk["Domain"])
                domainRoster.append(fqdn)
            domainRoster = sorted(set(domainRoster))

        except AssertionError as ae:
            self.warning(ae)

        return domainRoster

    def handle_event(self, event):
        subDomains = self.extractSubdomainsFromRaw(self.apiTechnologyRequest(event.data))
        for site in subDomains:
            self.emit_event(site, "DNS_NAME", source=event)