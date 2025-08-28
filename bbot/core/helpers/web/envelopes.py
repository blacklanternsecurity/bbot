import json
import base64
import binascii
import xmltodict
from contextlib import suppress
from urllib.parse import unquote, quote
from xml.parsers.expat import ExpatError

from bbot.core.helpers.misc import is_printable


# TODO: This logic is perfect for extracting params. We should expand it outwards to include other higher-level envelopes:
#    - QueryStringEnvelope
#    - MultipartFormEnvelope
#    - HeaderEnvelope
#    - CookieEnvelope
#
# Once we start ingesting HTTP_REQUEST events, this will make them instantly fuzzable


class EnvelopeChildTracker(type):
    """
    Keeps track of all the child envelope classes
    """

    children = []

    def __new__(mcs, name, bases, class_dict):
        # Create the class
        cls = super().__new__(mcs, name, bases, class_dict)
        # Don't register the base class itself
        if bases and not name.startswith("Base"):  # Only register if it has base classes (i.e., is a child)
            EnvelopeChildTracker.children.append(cls)
            EnvelopeChildTracker.children.sort(key=lambda x: x.priority)
        return cls


class BaseEnvelope(metaclass=EnvelopeChildTracker):
    __slots__ = ["subparams", "selected_subparam", "singleton"]

    # determines the order of the envelope detection
    priority = 5
    # whether the envelope is the final format, e.g. raw text/binary
    end_format = False
    ignore_exceptions = (Exception,)
    envelope_classes = EnvelopeChildTracker.children
    # transparent envelopes (i.e. TextEnvelope) are not counted as envelopes or included in the finding descriptions
    transparent = False

    def __init__(self, s):
        unpacked_data = self.unpack(s)

        if self.end_format:
            inner_envelope = unpacked_data
        else:
            inner_envelope = self.detect(unpacked_data)

        self.selected_subparam = None
        # if we have subparams, our inner envelope will be a dictionary
        if isinstance(inner_envelope, dict):
            self.subparams = inner_envelope
            self.singleton = False
        # otherwise if we just have one value, we make a dictionary with a default key
        else:
            self.subparams = {"__default__": inner_envelope}
            self.singleton = True

    @property
    def final_envelope(self):
        try:
            return self.unpacked_data(recursive=False).final_envelope
        except AttributeError:
            return self

    @property
    def friendly_name(self):
        if self.friendly_name:
            return self.friendly_name
        else:
            return self.name

    def pack(self, data=None):
        if data is None:
            data = self.unpacked_data(recursive=False)
            with suppress(AttributeError):
                data = data.pack()
        return self._pack(data)

    def unpack(self, s):
        return self._unpack(s)

    def _pack(self, s):
        """
        Encodes the string using the class's unique encoder (adds the outer envelope)
        """
        raise NotImplementedError("Envelope.pack() must be implemented")

    def _unpack(self, s):
        """
        Decodes the string using the class's unique encoder (removes the outer envelope)
        """
        raise NotImplementedError("Envelope.unpack() must be implemented")

    def unpacked_data(self, recursive=True):
        try:
            unpacked = self.subparams["__default__"]
            if recursive:
                with suppress(AttributeError):
                    return unpacked.unpacked_data(recursive=recursive)
            return unpacked
        except KeyError:
            return self.subparams

    @classmethod
    def detect(cls, s):
        """
        Detects the type of envelope used to encode the packed_data
        """
        if not isinstance(s, str):
            raise ValueError(f"Invalid data passed to detect(): {s} ({type(s)})")
        # if the value is empty, we just return the text envelope
        if not s.strip():
            return TextEnvelope(s)
        for envelope_class in cls.envelope_classes:
            with suppress(*envelope_class.ignore_exceptions):
                envelope = envelope_class(s)
                if envelope is not False:
                    # make sure the envelope is not just the original string, to prevent unnecessary envelope detection. For example, "10" is technically valid JSON, but nothing is being encapsulated
                    if str(envelope.unpacked_data()) == s:
                        return TextEnvelope(s)
                    else:
                        return envelope
                del envelope
        raise Exception(f"No envelope detected for data: '{s}' ({type(s)})")

    def get_subparams(self, key=None, data=None, recursive=True):
        if data is None:
            data = self.unpacked_data(recursive=recursive)
        if key is None:
            key = []

        if isinstance(data, dict):
            for k, v in data.items():
                full_key = key + [k]
                if isinstance(v, dict):
                    yield from self.get_subparams(full_key, v)
                else:
                    yield full_key, v
        else:
            yield [], data

    def get_subparam(self, key=None, recursive=True):
        if key is None:
            key = self.selected_subparam
        envelope = self
        if recursive:
            envelope = self.final_envelope
        data = envelope.unpacked_data(recursive=False)
        if key is None:
            if envelope.singleton:
                key = []
            else:
                raise ValueError("No subparam selected")
        else:
            for segment in key:
                data = data[segment]
        return data

    def set_subparam(self, key=None, value=None, recursive=True):
        envelope = self
        if recursive:
            envelope = self.final_envelope

        # if there's only one value to set, we can just set it directly
        if envelope.singleton:
            envelope.subparams["__default__"] = value
            return

        # if key isn't specified, use the selected subparam
        if key is None:
            key = self.selected_subparam
        if key is None:
            raise ValueError(f"{self} -> {envelope}: No subparam selected")

        data = envelope.unpacked_data(recursive=False)
        for segment in key[:-1]:
            data = data[segment]
        data[key[-1]] = value

    @property
    def name(self):
        return self.__class__.__name__

    @property
    def num_envelopes(self):
        num_envelopes = 0 if self.transparent else 1
        if self.end_format:
            return num_envelopes
        for envelope in self.subparams.values():
            with suppress(AttributeError):
                num_envelopes += envelope.num_envelopes
        return num_envelopes

    @property
    def summary(self):
        if self.transparent:
            return ""
        self_string = f"{self.friendly_name}"
        with suppress(AttributeError):
            child_envelope = self.unpacked_data(recursive=False)
            child_summary = child_envelope.summary
            if child_summary:
                self_string += f" -> {child_summary}"

        if self.selected_subparam:
            self_string += f" [{'.'.join(self.selected_subparam)}]"
        return self_string

    def to_dict(self):
        return self.summary

    def __str__(self):
        return self.summary

    __repr__ = __str__


class HexEnvelope(BaseEnvelope):
    """
    Hexadecimal encoding
    """

    friendly_name = "Hexadecimal-Encoded"

    ignore_exceptions = (ValueError, UnicodeDecodeError)

    def _pack(self, s):
        return s.encode().hex()

    def _unpack(self, s):
        return bytes.fromhex(s).decode()


class B64Envelope(BaseEnvelope):
    """
    Base64 encoding
    """

    friendly_name = "Base64-Encoded"

    ignore_exceptions = (binascii.Error, UnicodeDecodeError, ValueError)

    def unpack(self, s):
        # it's easy to have a small value that accidentally decodes to base64
        if len(s) < 8 and not s.endswith("="):
            raise ValueError("Data is too small to be sure")
        return super().unpack(s)

    def _pack(self, s):
        return base64.b64encode(s.encode()).decode()

    def _unpack(self, s):
        return base64.b64decode(s).decode()


class URLEnvelope(BaseEnvelope):
    """
    URL encoding
    """

    friendly_name = "URL-Encoded"

    def unpack(self, s):
        unpacked = super().unpack(s)
        if unpacked == s:
            raise ValueError("Data is not URL-encoded")
        return unpacked

    def _pack(self, s):
        return quote(s)

    def _unpack(self, s):
        return unquote(s)


class TextEnvelope(BaseEnvelope):
    """
    Text encoding
    """

    end_format = True
    # lowest priority means text is the ultimate fallback
    priority = 10
    transparent = True
    ignore_exceptions = ()

    def _pack(self, s):
        return s

    def _unpack(self, s):
        if not is_printable(s):
            raise ValueError(f"Non-printable data detected in TextEnvelope: '{s}' ({type(s)})")
        return s


# class BinaryEnvelope(BaseEnvelope):
#     """
#     Binary encoding
#     """
#     end_format = True

#     def pack(self, s):
#         return s

#     def unpack(self, s):
#         if is_printable(s):
#             raise Exception("Non-binary data detected in BinaryEnvelope")
#         return s


class JSONEnvelope(BaseEnvelope):
    """
    JSON encoding
    """

    friendly_name = "JSON-formatted"
    end_format = True
    priority = 8
    ignore_exceptions = (json.JSONDecodeError,)

    def _pack(self, s):
        return json.dumps(s)

    def _unpack(self, s):
        return json.loads(s)


class XMLEnvelope(BaseEnvelope):
    """
    XML encoding
    """

    friendly_name = "XML-formatted"
    end_format = True
    priority = 9
    ignore_exceptions = (ExpatError,)

    def _pack(self, s):
        return xmltodict.unparse(s)

    def _unpack(self, s):
        return xmltodict.parse(s)
