'''# Example usage
image_url = "http://example.com/image.jpg"
provided_hash = "3:hQFtqkN6x6lWifRtC6sXxPwlAO5JngRc:hMtqkN6RlWiC6Pwl2Jn"
is_similar = is_image_hash_similar(image_url, provided_hash)
print(f"Is the image hash similar? {is_similar}")'''

from bbot.modules.base import BaseModule
import xml.etree.ElementTree as ET
import requests
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
    options_desc = {"fuzzy_hash": "Provided CTPH hash to compare to"}
    scope_distance_modifier = 2

    async def setup(self):
        self.fuzzy_hash = self.config.get("fuzzy_hash", "1234")
        return True

    async def handle_event(self, event):
        cloud_tags = (t for t in event.tags if t.startswith("cloud-"))
        if any(t.endswith("-amazon") or t.endswith("-digitalocean") for t in cloud_tags):
            await self.handle_url(event)

    async def handle_url(self, event):
        resp_body = event.data.get("body", None)
        url_list = get_image_urls(resp_body)
        for url in url_list:
            similar_score = is_image_hash_similar(url, self.fuzzy_hash)
            if similar_score >= self.confidence:
                data = {
                "description": f"Identified matched similar score above {self.confidence}",
                "url": url
                }
                self.emit_event("data", "FIDNING", event)

    def get_image_urls(response_body):
    """
    Extracts all image URLs from an HTTP response.

    Parameters:
    - response: The HTTP response object from requests.

    Returns:
    - A list of strings, where each string is the URL of an image found in the response.
    """
    # Parse the HTML content of the response
    soup = BeautifulSoup(response.content, 'html.parser')
    
    # Find all <img> tags in the HTML
    img_tags = soup.find_all('img')
    
    # Extract the URLs of the images, handling both absolute and relative URLs
    image_urls = []
    for img in img_tags:
        src = img.get('src')
        if src:
            # Convert relative URLs to absolute URLs
            absolute_src = urljoin(response.url, src)
            image_urls.append(absolute_src)
    
    return image_urls
        return

    def download_image(url):
    """Download image and return its content."""
    response = requests.get(url)
    response.raise_for_status()  # Raises an exception for HTTP errors.
    return response.content

    def compute_hash(image_content):
        """Compute the ssdeep hash of the given image content."""
        # ssdeep.hash() expects a string or bytes, so ensure the input is correctly formatted.
        return ssdeep.hash(image_content)

    def compare_hashes(hash1, hash2):
        """Compare two ssdeep hashes and return their similarity score."""
        return ssdeep.compare(hash1, hash2)

    def is_image_hash_similar(image_url, provided_hash):
        """Determine if the hash of the image at the given URL is similar to the provided hash."""
        image_content = download_image(image_url)
        image_hash = compute_hash(image_content)
        similarity_score = compare_hashes(image_hash, provided_hash)
        
        # You may choose a threshold for similarity; the exact value depends on your requirements.
        # ssdeep.compare() returns a value from 0 to 100 indicating the percentage of similarity.
        return similarity_score