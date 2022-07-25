# Stolen from https://github.com/blacklanternsecurity/TREVORspray who stole it from https://github.com/byt3bl33d3r/SprayingToolkit/blob/master/core/utils/ntlmdecoder.py

import base64
import struct
import string
import collections
import logging
from binascii import hexlify

log = logging.getLogger("trevorspray.util.ntlmdecoder")

flags_tbl_str = """0x00000001  Negotiate Unicode
0x00000002  Negotiate OEM
0x00000004  Request Target
0x00000008  unknown
0x00000010  Negotiate Sign
0x00000020  Negotiate Seal
0x00000040  Negotiate Datagram Style
0x00000080  Negotiate Lan Manager Key
0x00000100  Negotiate Netware
0x00000200  Negotiate NTLM
0x00000400  unknown
0x00000800  Negotiate Anonymous
0x00001000  Negotiate Domain Supplied
0x00002000  Negotiate Workstation Supplied
0x00004000  Negotiate Local Call
0x00008000  Negotiate Always Sign
0x00010000  Target Type Domain
0x00020000  Target Type Server
0x00040000  Target Type Share
0x00080000  Negotiate NTLM2 Key
0x00100000  Request Init Response
0x00200000  Request Accept Response
0x00400000  Request Non-NT Session Key
0x00800000  Negotiate Target Info
0x01000000  unknown
0x02000000  unknown
0x04000000  unknown
0x08000000  unknown
0x10000000  unknown
0x20000000  Negotiate 128
0x40000000  Negotiate Key Exchange
0x80000000  Negotiate 56"""

flags_tbl = [line.split("  ") for line in flags_tbl_str.split("\n")]
flags_tbl = [(int(x, base=16), y) for x, y in flags_tbl]
VALID_CHRS = set(string.ascii_letters + string.digits + string.punctuation)


def flags_lst(flags):
    return [desc for val, desc in flags_tbl if val & flags]


def flags_str(flags):
    return ", ".join('"%s"' % s for s in flags_lst(flags))


def clean_str(st):
    return "".join((s if s in VALID_CHRS else "?") for s in st)


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

    def __str__(self):
        st = "%s'%s' [%s] (%db @%d)" % (
            "u" if self.utf16 else "",
            clean_str(self.string),
            hexlify(self.raw),
            self.length,
            self.offset,
        )
        if self.alloc != self.length:
            st += " alloc: %d" % self.alloc
        return st


msg_types = collections.defaultdict(lambda: "UNKNOWN")
msg_types[1] = "Request"
msg_types[2] = "Challenge"
msg_types[3] = "Response"

target_field_types = collections.defaultdict(lambda: "UNKNOWN")
target_field_types[0] = "TERMINATOR"
target_field_types[1] = "NetBIOS_Computer_Name"
target_field_types[2] = "NetBIOS_Domain_Name"
target_field_types[3] = "FQDN"
target_field_types[4] = "DNS_Domain_name"
target_field_types[5] = "DNS_Tree_Name"
target_field_types[7] = "Timestamp"


def opt_str_struct(name, st, offset):
    nxt = st[offset : offset + 8]
    if len(nxt) == 8:
        hdr_tup = struct.unpack("<hhi", nxt)
        print("%s: %s" % (name, StrStruct(hdr_tup, st)))
    else:
        print("%s: [omitted]" % name)


def opt_inline_str(name, st, offset, sz):
    nxt = st[offset : offset + sz]
    if len(nxt) == sz:
        print("%s: '%s'" % (name, clean_str(nxt)))
    else:
        print("%s: [omitted]" % name)


def decode_ntlm_challenge(st):
    hdr_tup = struct.unpack("<hhiiQ", st[12:32])

    parsed_challange = {}

    # print("Target Name: %s" % StrStruct(hdr_tup[0:3], st))
    # print("Challenge: 0x%x" % hdr_tup[4])

    flags = hdr_tup[3]

    # opt_str_struct("Context", st, 32)

    nxt = st[40:48]
    if len(nxt) == 8:
        hdr_tup = struct.unpack("<hhi", nxt)
        tgt = StrStruct(hdr_tup, st)

        output = "Target: [block] (%db @%d)" % (tgt.length, tgt.offset)
        if tgt.alloc != tgt.length:
            output += " alloc: %d" % tgt.alloc
        # print(output)

        raw = tgt.raw
        pos = 0

        while pos + 4 < len(raw):
            rec_hdr = struct.unpack("<hh", raw[pos : pos + 4])
            rec_type_id = rec_hdr[0]
            rec_type = target_field_types[rec_type_id]
            rec_sz = rec_hdr[1]
            subst = raw[pos + 4 : pos + 4 + rec_sz]
            try:
                parsed_challange[rec_type] = subst.replace(b"\x00", b"").decode()
                # print("    %s (%d): %s" % (rec_type, rec_type_id, subst.replace(b'\x00', b'').decode()))
            except UnicodeDecodeError:
                parsed_challange[rec_type] = subst.replace(b"\x00", b"")
                # print("    %s (%d): %s" % (rec_type, rec_type_id, subst.replace(b'\x00', b'')))
            pos += 4 + rec_sz

    # opt_inline_str("OS Ver", st, 48, 8)

    # print("Flags: 0x%x [%s]" % (flags, flags_str(flags)))
    return parsed_challange


def ntlmdecode(authenticate_header):
    #  _, st_raw = authenticate_header.split(',')[0].split()
    try:
        st = base64.b64decode(authenticate_header)
    except Exception as e:
        print(e)
        # raise Exception(f"Input seems to be a non-valid base64-encoded string: '{authenticate_header}'")

    if not st[:8] == b"NTLMSSP\x00":
        raise Exception("NTLMSSP header not found at start of input string")

    ver_tup = struct.unpack("<i", st[8:12])
    ver = ver_tup[0]

    return decode_ntlm_challenge(st)

    raise Exception(f"Unknown message structure.  Have a raw (hex-encoded) message: {hexlify(st)}")


testheader = "TlRMTVNTUAACAAAAHgAeADgAAAAVgorilwL+bvnVipUAAAAAAAAAAJgAmABWAAAACgBjRQAAAA9XAEkATgAtAFMANAAyAE4ATwBCAEQAVgBUAEsAOAACAB4AVwBJAE4ALQBTADQAMgBOAE8AQgBEAFYAVABLADgAAQAeAFcASQBOAC0AUwA0ADIATgBPAEIARABWAFQASwA4AAQAHgBXAEkATgAtAFMANAAyAE4ATwBCAEQAVgBUAEsAOAADAB4AVwBJAE4ALQBTADQAMgBOAE8AQgBEAFYAVABLADgABwAIAHUwOZlfoNgBAAAAAA=="

test = ntlmdecode(testheader)

print(test)
print(type(test))
