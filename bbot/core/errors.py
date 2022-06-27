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


class ModuleLoadError(BBOTError):
    pass


class ConfigLoadError(BBOTError):
    pass


class HttpCompareError(BBOTError):
    pass
