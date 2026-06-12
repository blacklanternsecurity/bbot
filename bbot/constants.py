SCAN_STATUS_QUEUED = 0
SCAN_STATUS_NOT_STARTED = 1
SCAN_STATUS_STARTING = 2
SCAN_STATUS_RUNNING = 3
SCAN_STATUS_FINISHING = 4
SCAN_STATUS_ABORTING = 5
SCAN_STATUS_FINISHED = 6
SCAN_STATUS_FAILED = 7
SCAN_STATUS_ABORTED = 8


SCAN_STATUSES = {
    "QUEUED": SCAN_STATUS_QUEUED,
    "NOT_STARTED": SCAN_STATUS_NOT_STARTED,
    "STARTING": SCAN_STATUS_STARTING,
    "RUNNING": SCAN_STATUS_RUNNING,
    "FINISHING": SCAN_STATUS_FINISHING,
    "ABORTING": SCAN_STATUS_ABORTING,
    "FINISHED": SCAN_STATUS_FINISHED,
    "FAILED": SCAN_STATUS_FAILED,
    "ABORTED": SCAN_STATUS_ABORTED,
}

SCAN_STATUS_CODES = {v: k for k, v in SCAN_STATUSES.items()}


def is_valid_scan_status(status):
    """
    Check if a status is a valid scan status
    """
    return status in SCAN_STATUSES


def is_valid_scan_status_code(status):
    """
    Check if a status is a valid scan status code
    """
    return status in SCAN_STATUS_CODES


def get_scan_status_name(status):
    """
    Convert a numeric scan status code to a string status name
    """
    try:
        if isinstance(status, str):
            if not is_valid_scan_status(status):
                raise ValueError(f"Invalid scan status: {status}")
            return status
        elif isinstance(status, int):
            return SCAN_STATUS_CODES[status]
        else:
            raise ValueError(f"Invalid scan status: {status} (must be int or str)")
    except KeyError:
        raise ValueError(f"Invalid scan status: {status}")


def get_scan_status_code(status):
    """
    Convert a scan status string to a numeric status code
    """
    try:
        if isinstance(status, int):
            if not is_valid_scan_status_code(status):
                raise ValueError(f"Invalid scan status code: {status}")
            return status
        elif isinstance(status, str):
            return SCAN_STATUSES[status]
        else:
            raise ValueError(f"Invalid scan status: {status} (must be int or str)")
    except KeyError:
        raise ValueError(f"Invalid scan status: {status}")
