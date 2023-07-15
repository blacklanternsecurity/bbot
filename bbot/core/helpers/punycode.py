import re
import idna


def split_text(text):
    # Split text into segments by special characters
    # We assume that only alphanumeric segments should be encoded
    if not isinstance(text, str):
        raise ValueError(f"data must be a string, not {type(text)}")
    segments = re.split(r"([a-z0-9-]+)", text)
    return segments


def smart_encode_punycode(text: str) -> str:
    """
    ドメイン.テスト --> xn--eckwd4c7c.xn--zckzah
    """
    segments = split_text(text)
    result_segments = []

    for segment in segments:
        try:
            if re.match(r"^[a-z0-9-]+$", segment):  # Only encode alphanumeric segments
                segment = idna.encode(segment).decode(errors="ignore")
        except UnicodeError:
            pass  # If encoding fails, leave the segment as it is

        result_segments.append(segment)

    return "".join(result_segments)


def smart_decode_punycode(text: str) -> str:
    """
    xn--eckwd4c7c.xn--zckzah --> ドメイン.テスト
    """
    segments = split_text(text)
    result_segments = []

    for segment in segments:
        try:
            if re.match(r"^[a-z0-9-]+$", segment):  # Only decode alphanumeric segments
                segment = idna.decode(segment)
        except UnicodeError:
            pass  # If decoding fails, leave the segment as it is

        result_segments.append(segment)

    return "".join(result_segments)
