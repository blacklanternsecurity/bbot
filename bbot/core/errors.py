class BBotError(Exception):
    pass


class ScanCancelledError(BBotError):
    pass


class ArgumentError(BBotError):
    pass


class ValidationError(BBotError):
    pass
