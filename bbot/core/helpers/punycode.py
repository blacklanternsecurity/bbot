import re
import idna
from contextlib import suppress


def split_text(text):
    # Split text into segments by special characters
    # We assume that only alphanumeric segments should be encoded
    segments = re.split(r"([^\w-]+)", text)
    return segments


def smart_encode_punycode(text: str) -> str:
    segments = split_text(text)
    result_segments = []

    for segment in segments:
        try:
            if re.match(r"^[\w-]+$", segment):  # Only encode alphanumeric segments
                # segment = segment.encode('idna').decode('ascii')
                segment = idna.encode(segment).decode(errors="ignore")
        except UnicodeError:
            pass  # If encoding fails, leave the segment as it is

        result_segments.append(segment)

    return "".join(result_segments)


def smart_decode_punycode(text: str) -> str:
    segments = split_text(text)
    result_segments = []

    for segment in segments:
        try:
            if re.match(r"^[\w-]+$", segment):  # Only decode alphanumeric segments
                # segment = segment.encode('ascii').decode('idna')
                segment = idna.decode(segment)
        except UnicodeError:
            pass  # If decoding fails, leave the segment as it is

        result_segments.append(segment)

    return "".join(result_segments)
