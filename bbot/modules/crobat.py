from bbot.modules.templates.subdomain_enum import subdomain_enum


class crobat(subdomain_enum):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    # tag "subdomain-enum" removed 2023-02-24 because API is offline
    flags = ["passive", "safe"]
    meta = {"description": "Query Project Crobat for subdomains"}
    base_url = "https://sonar.omnisint.io"
