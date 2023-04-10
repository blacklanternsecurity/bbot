# adopted from https://github.com/bugcrowd/HUNT

import re
from bbot.modules.base import BaseModule
import math
from collections import Counter
from bs4 import BeautifulSoup, NavigableString

def shannon_entropy(s):
    counts = Counter(s)
    length = len(s)
    entropy = 0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def extract_strings(soup, path=None, max_length=100):
    if path is None:
        path = []

    strings = []

    for idx, child in enumerate(soup.children):
        current_path = path + [(soup.name, idx)]

        if isinstance(child, NavigableString):
            content = child.strip()
            if content and len(content) <= max_length:
                strings.append((content, current_path))
        else:
            strings.extend(extract_strings(child, current_path, max_length))

    return strings

def find_high_entropy_strings(html, threshold, max_length=120):
    soup = BeautifulSoup(html, 'lxml')
    strings_with_context = extract_strings(soup, max_length=max_length)

    high_entropy_strings = []

    for string, path in strings_with_context:
        entropy = shannon_entropy(string)
        if entropy > threshold:
            high_entropy_strings.append((string, entropy, path))

    return high_entropy_strings


class crypto_hunter(BaseModule):

    entropy_threshold = 3.5

    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["FINDING"]
    flags = ["active", "safe", "web-basic", "web-thorough"]
    meta = {"description": "test"}

    def handle_event(self, event):

        self.hugeinfo(event)
        body = event.data.get("body", "")
        high_entropy_strings = find_high_entropy_strings(body, self.entropy_threshold)
        #self.emit_event(data, "FINDING", event)
        print(f"Strings with entropy higher than {self.entropy_threshold}:")
        for string, entropy, path in high_entropy_strings:
            print(f"{string}: {entropy:.2f} (Path: {'/'.join(f'<{tag}[{pos}]>' for tag, pos in path)})")