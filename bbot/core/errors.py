from requests.exceptions import RequestException  # noqa F401


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


class ConfigLoadError(BBOTError):
    pass


class HttpCompareError(BBOTError):
    pass


class DirectoryCreationError(BBOTError):
    pass


class DirectoryDeletionError(BBOTError):
    pass


class NTLMError(BBOTError):
    pass


class InteractshError(BBOTError):
    pass


class WordlistError(BBOTError):
    pass
