from bbot.modules.base import BaseModule
from bbot.core.helpers.misc import parse_list_string
import xml.etree.ElementTree as ET
import ssdeep
from bs4 import BeautifulSoup
from urllib.parse import urljoin


class fuzzy_image_hash(BaseModule):
    """
    Compares a context-triggered piecewise hash (CTPH) against a provided hash for images
    """

    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["FINDING"]
    meta = {
        "description": "Using a provided CTPH compares it against any image encountered within a website."
    }
    flags = ["passive", "safe"]
    options = {
        "fuzzy_hashes": "",
        "confidence": 90,
    }
    options_desc = {
        "fuzzy_hashes": "Provided CTPH hash(es) to compare to",
        "confidence": "Confidence level threshold for comparing hashes."
     }
    scope_distance_modifier = 2

    async def setup(self):
        try:
            self.fuzzy_hashes = parse_list_string(self.config.get("fuzzy_hashes", ""))
        except ValueError as e:
            self.warning(f"Error parsing hashes: {e}")
        if not self.fuzzy_hashes:
            return None, "Must set fuzzy hash value"
        self.confidence = self.config.get("confidence")
        if not self.confidence:
            self.confidence = 90
        else:
            return True

    async def handle_event(self, event):
        url_list = self.get_image_urls(event.data)
        if url_list == None or url_list == [] or url_list == False:
            return False
        for url in url_list:
            image = await self.helpers.request(url, allow_redirects=True)
            image_hash = ssdeep.hash(image.content)
            for fuzzy_hash in self.fuzzy_hashes:
                similar_score = ssdeep.compare(image_hash, fuzzy_hash)
                if similar_score >= self.confidence:
                    data = {
                    "description": f"Identified matched similar score above {self.confidence}, matching hash: {fuzzy_hash}",
                    "url": url,
                    "host": event.host
                    }
                    await self.emit_event(data, "FINDING", event)

    def get_image_urls(self, data):
        """
        Extracts all image URLs from an HTTP response.

        Parameters:
        - response: The HTTP response object from requests.

        Returns:
        - A list of strings, where each string is the URL of an image found in the response.
        """
        # Parse the HTML content of the response
        content = data.get("body", None)
        if content == None:
            return False
        soup = BeautifulSoup(content, 'html.parser')
        
        # Find all <img> tags in the HTML
        img_tags = soup.find_all('img')
        
        # Extract the URLs of the images, handling both absolute and relative URLs
        image_urls = []
        for img in img_tags:
            src = img.get('src')
            if src:
                # Convert relative URLs to absolute URLs
                absolute_src = urljoin(data["url"], src)
                image_urls.append(absolute_src)
        return image_urls