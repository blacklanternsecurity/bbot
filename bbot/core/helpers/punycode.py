import re
import idna


alphanum_regex = re.compile(r"([\w-]+)")
alphanum_anchored = re.compile(r"^[\w-]+$")


def split_text(text):
    # Split text into segments by special characters
    # We assume that only alphanumeric segments should be encoded
    if not isinstance(text, str):
        raise ValueError(f"data must be a string, not {type(text)}")
    segments = alphanum_regex.split(text)
    return segments


def smart_encode_punycode(text: str) -> str:
    """
    ドメイン.テスト --> xn--eckwd4c7c.xn--zckzah
    """
    segments = split_text(text)
    result_segments = []

    for segment in segments:
        try:
            if alphanum_anchored.match(segment):  # Only encode alphanumeric segments
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
            if alphanum_anchored.match(segment):  # Only decode alphanumeric segments
                segment = idna.decode(segment)
        except UnicodeError:
            pass  # If decoding fails, leave the segment as it is

        result_segments.append(segment)

    return "".join(result_segments)
