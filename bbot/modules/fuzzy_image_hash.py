from bbot.modules.base import BaseModule
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
        "fuzzy_hash": "",
        "confidence": 90,
    }
    options_desc = {"fuzzy_hash": "Provided CTPH hash to compare to", "confidence": "Confidence level threshold for comparing hashes."}
    scope_distance_modifier = 2

    async def setup(self):
        self.fuzzy_hash = self.config.get("fuzzy_hash")
        if not self.fuzzy_hash:
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
            similar_score = await self.is_image_hash_similar(url, self.fuzzy_hash)
            if similar_score >= self.confidence:
                data = {
                "description": f"Identified matched similar score above {self.confidence}",
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

    async def download_image(self, url):
        """Download image and return its content."""
        response = await self.helpers.request(url)
        # Might need to refactor this to check for HTTP rerrors since helpers doesn't have a raise_for_status function
        # response.raise_for_status()  # Raises an exception for HTTP errors.
        return response.content

    def compute_hash(self, image_content):
        """Compute the ssdeep hash of the given image content."""
        # ssdeep.hash() expects a string or bytes, so ensure the input is correctly formatted.
        return ssdeep.hash(image_content)

    def compare_hashes(self, hash1, hash2):
        """Compare two ssdeep hashes and return their similarity score."""
        return ssdeep.compare(hash1, hash2)

    async def is_image_hash_similar(self, image_url, provided_hash):
        """Determine if the hash of the image at the given URL is similar to the provided hash."""
        image_content = await self.download_image(image_url)
        image_hash = self.compute_hash(image_content)
        similarity_score = self.compare_hashes(image_hash, provided_hash)
        
        # You may choose a threshold for similarity; the exact value depends on your requirements.
        # ssdeep.compare() returns a value from 0 to 100 indicating the percentage of similarity.
        return similarity_score
