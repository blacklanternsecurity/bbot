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
    Encodes a given string using Punycode, while leaving non-alphanumeric segments untouched.

    Args:
        text (str): The string to be encoded.

    Returns:
        str: The Punycode encoded string.

    Examples:
        >>> smart_encode_punycode("ドメイン.テスト")
        "xn--eckwd4c7c.xn--zckzah"
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
    Decodes a given Punycode encoded string, while leaving non-alphanumeric segments untouched.

    Args:
        text (str): The Punycode encoded string to be decoded.

    Returns:
        str: The decoded string.

    Examples:
        >>> smart_decode_punycode("xn--eckwd4c7c.xn--zckzah")
        "ドメイン.テスト"
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
