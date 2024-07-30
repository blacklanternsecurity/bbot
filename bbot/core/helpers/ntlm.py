# Stolen from https://github.com/blacklanternsecurity/TREVORspray who stole it from https://github.com/byt3bl33d3r/SprayingToolkit/blob/master/core/utils/ntlmdecoder.py

import base64
import struct
import logging
import collections

from bbot.errors import NTLMError

log = logging.getLogger("bbot.core.helpers.ntlm")


class StrStruct(object):
    def __init__(self, pos_tup, raw):
        length, alloc, offset = pos_tup
        self.length = length
        self.alloc = alloc
        self.offset = offset
        self.raw = raw[offset : offset + length]
        self.utf16 = False

        if len(self.raw) >= 2 and self.raw[1] == "\0":
            self.string = self.raw.decode("utf-16")
            self.utf16 = True
        else:
            self.string = self.raw


target_field_types = collections.defaultdict(lambda: "UNKNOWN")
target_field_types[0] = "TERMINATOR"
target_field_types[1] = "NetBIOS_Computer_Name"
target_field_types[2] = "NetBIOS_Domain_Name"
target_field_types[3] = "FQDN"
target_field_types[4] = "DNS_Domain_name"
target_field_types[5] = "DNS_Tree_Name"
target_field_types[7] = "Timestamp"


def decode_ntlm_challenge(st):
    hdr_tup = struct.unpack("<hhiiQ", st[12:32])
    parsed_challenge = {}

    nxt = st[40:48]
    if len(nxt) == 8:
        hdr_tup = struct.unpack("<hhi", nxt)
        tgt = StrStruct(hdr_tup, st)

        output = "Target: [block] (%db @%d)" % (tgt.length, tgt.offset)
        if tgt.alloc != tgt.length:
            output += " alloc: %d" % tgt.alloc

        raw = tgt.raw
        pos = 0

        while pos + 4 < len(raw):
            rec_hdr = struct.unpack("<hh", raw[pos : pos + 4])
            rec_type_id = rec_hdr[0]
            rec_type = target_field_types[rec_type_id]
            rec_sz = rec_hdr[1]
            subst = raw[pos + 4 : pos + 4 + rec_sz]
            try:
                parsed_challenge[rec_type] = subst.replace(b"\x00", b"").decode()
            except UnicodeDecodeError:
                parsed_challenge[rec_type] = subst.replace(b"\x00", b"")
            pos += 4 + rec_sz

    return parsed_challenge


def ntlmdecode(authenticate_header):
    try:
        st = base64.b64decode(authenticate_header)
    except Exception:
        raise NTLMError(f"Failed to decode NTLM challenge: {authenticate_header}")

    if not st[:8] == b"NTLMSSP\x00":
        raise NTLMError("NTLMSSP header not found at start of input string")

    try:
        return decode_ntlm_challenge(st)
    except Exception as e:
        raise NTLMError(f"Failed to parse NTLM challenge: {authenticate_header}: {e}")
