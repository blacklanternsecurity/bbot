import re
import idna


split_regex = re.compile(r"([/:@\[\]]+)")


def split_text(text):
    # We have to split this way in order to handle URLs and email addresses
    # which the idna library is not equipped to deal with
    if not isinstance(text, str):
        raise ValueError(f"data must be a string, not {type(text)}")
    segments = split_regex.split(text)
    return segments


def smart_encode_punycode(text: str) -> str:
    """
    ドメイン.テスト --> xn--eckwd4c7c.xn--zckzah
    """
    segments = split_text(text)
    result_segments = []

    for segment in segments:
        try:
            if not split_regex.match(segment):
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
            segment = idna.decode(segment)
        except UnicodeError:
            pass  # If decoding fails, leave the segment as it is

        result_segments.append(segment)

    return "".join(result_segments)
