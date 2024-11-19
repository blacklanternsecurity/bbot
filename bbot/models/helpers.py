from datetime import datetime
from typing_extensions import Annotated
from pydantic.functional_validators import AfterValidator


def naive_datetime_validator(d: datetime) -> datetime:
    """
    Converts all dates into UTC, then drops timezone information.

    This is needed to prevent inconsistencies in sqlite, because it is timezone-naive.
    """
    # drop timezone info
    return d.replace(tzinfo=None)


def naive_utc_now() -> datetime:
    return naive_datetime_validator(datetime.now())


NaiveUTC = Annotated[datetime, AfterValidator(naive_datetime_validator)]
