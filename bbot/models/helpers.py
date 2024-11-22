from datetime import datetime
from zoneinfo import ZoneInfo


def utc_datetime_validator(d: datetime) -> datetime:
    """
    Converts all dates into UTC
    """
    if d.tzinfo is not None:
        return d.astimezone(ZoneInfo("UTC"))
    else:
        return d.replace(tzinfo=ZoneInfo("UTC"))


def utc_now() -> datetime:
    return datetime.now(ZoneInfo("UTC"))


def utc_now_timestamp() -> datetime:
    return utc_now().timestamp()
