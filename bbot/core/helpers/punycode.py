import idna
from contextlib import suppress


def smart_decode_punycode(data):
    """
    xn--eckwd4c7c.xn--zckzah --> ドメイン.テスト
    """
    if not isinstance(data, str):
        raise ValueError(f"data must be a string, not {type(data)}")
    if "xn--" in data:
        with suppress(UnicodeError):
            parts = data.split("@")
            return "@".join(idna.decode(p) for p in parts)
    return data


def smart_encode_punycode(data):
    """
    ドメイン.テスト --> xn--eckwd4c7c.xn--zckzah
    """
    if not isinstance(data, str):
        raise ValueError(f"data must be a string, not {type(data)}")
    with suppress(UnicodeError):
        parts = data.split("@")
        return "@".join(idna.encode(p).decode(errors="ignore") for p in parts)
    return data
