import requests
import re
from bs4 import BeautifulSoup
from bbot.modules.base import BaseModule

class peoplecrawl(BaseModule):
    
    watched_events = ["DNS_NAME"]
    produced_events = ["SOCMINT"]
    flags = ["passive"]

    opts = {}

    optdescs = {
    }

    results = None

    social_media_regex = {
        "linkedin": r"(https?:\/\/)?(www\.)?linkedin\.com\/(in|company)\/[a-zA-Z0-9-]+\/?",
        "facebook": r"(https?:\/\/)?(www\.)?facebook\.com\/[a-zA-Z0-9\.]+\/?",
        "twitter": r"(https?:\/\/)?(www\.)?twitter\.com\/[a-zA-Z0-9_]{1,15}\/?",
        "github": r"(https?:\/\/)?(www\.)?github\.com\/[a-zA-Z0-9_-]+\/?",
        "instagram": r"(https?:\/\/)?(www\.)?instagram\.com\/[a-zA-Z0-9_\.]+\/?",
        "youtube": r"(https?:\/\/)?(www\.)?youtube\.com\/[a-zA-Z0-9_]+\/?",
        "bitbucket": r"(https?:\/\/)?(www\.)?bitbucket\.org\/[a-zA-Z0-9_-]+\/?",
        "gitlab": r"(https?:\/\/)?(www\.)?gitlab\.com\/[a-zA-Z0-9_-]+\/?"
    }

    def handle_event(self, event):
        domains = event.data.split()
        for domain in domains:
            try:
                response = requests.get(f"https://{domain}")
            except requests.exceptions.ConnectionError as e:
                print(f"Failed to connect to domain: {domain}")
                print(f"Error message: {str(e)}")
                continue

            soup = BeautifulSoup(response.text, 'html.parser')
            for platform, regex in self.social_media_regex.items():
                for link in soup.find_all('a', href=re.compile(regex)):
                    social_media_links = {
                        "platform": platform,
                        "url": link['href']
                    }
                    self.emit_event(social_media_links, 'SOCMINT', source=event)
