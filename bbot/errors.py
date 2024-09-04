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


class CurlError(BBOTError):
    pass


class PresetNotFoundError(BBOTError):
    pass


class EnableModuleError(BBOTError):
    pass


class EnableFlagError(BBOTError):
    pass


class BBOTArgumentError(BBOTError):
    pass


class PresetConditionError(BBOTError):
    pass


class PresetAbortError(PresetConditionError):
    pass


class BBOTEngineError(BBOTError):
    pass


class WebError(BBOTEngineError):
    pass


class DNSError(BBOTEngineError):
    pass


class ExcavateError(BBOTError):
    pass
