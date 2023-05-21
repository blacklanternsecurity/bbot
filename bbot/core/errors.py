from httpx import RequestError, ReadTimeout  # noqa


class BBOTError(Exception):
    pass


class ScanError(BBOTError):
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


class DNSError(BBOTError):
    pass


class CurlError(BBOTError):
    pass
