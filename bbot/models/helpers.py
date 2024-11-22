from datetime import UTC
from datetime import datetime
from typing_extensions import Annotated
from pydantic.functional_validators import AfterValidator


def utc_datetime_validator(d: datetime) -> datetime:
    """
    Converts all dates into UTC
    """
    if d.tzinfo is not None:
        return d.astimezone(UTC)
    else:
        return d.replace(tzinfo=UTC)


def utc_now() -> datetime:
    return datetime.now(UTC)


def utc_now_timestamp() -> datetime:
    return utc_now().timestamp()
