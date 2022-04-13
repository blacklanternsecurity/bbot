class BBOTError(Exception):
    pass


class ScanError(BBOTError):
    pass


class ScanCancelledError(BBOTError):
    pass


class ArgumentError(BBOTError):
    pass


class ValidationError(BBOTError):
    pass
