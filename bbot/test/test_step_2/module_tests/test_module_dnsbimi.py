from .base import ModuleTestBase

# Mock data is zone-file format. TXT character-strings must be quoted so that
# whitespace inside the payload is preserved (otherwise the zone-file lexer
# splits each token into its own character-string).
mock_bimi_txt_default = (
    '"v=BIMI1;l=https://bimi.test.localdomain/logo.svg; a=https://bimi.test.localdomain/certificate.pem"'
)
mock_bimi_txt_nondefault = (
    '"v=BIMI1; l=https://nondefault.thirdparty.tld/brand/logo.svg;'
    'a=https://nondefault.thirdparty.tld/brand/certificate.pem;"'
)

# What the modules emit in RAW_DNS_RECORD events: hickory's Display strips the
# surrounding quotes from TXT, returning the bare character-string content.
raw_bimi_txt_default = (
    "v=BIMI1;l=https://bimi.test.localdomain/logo.svg; a=https://bimi.test.localdomain/certificate.pem"
)
raw_bimi_txt_nondefault = "v=BIMI1; l=https://nondefault.thirdparty.tld/brand/logo.svg;a=https://nondefault.thirdparty.tld/brand/certificate.pem;"


class TestDnsbimi(ModuleTestBase):
    targets = ["test.localdomain"]
    modules_overrides = ["dnsbimi", "speculate"]
    config_overrides = {
        "modules": {"dnsbimi": {"emit_raw_dns_records": True, "selectors": "default,nondefault"}},
        "omit_event_types": ["HTTP_RESPONSE", "RAW_TEXT", "DNS_NAME_UNRESOLVED", "FILESYSTEM", "WEB_PARAMETER"],
    }

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "test.localdomain": {
                    "A": ["127.0.0.11"],
                },
                "bimi.test.localdomain": {
                    "A": ["127.0.0.22"],
                },
                "_bimi.test.localdomain": {
                    "A": ["127.0.0.33"],
                },
                "default._bimi.test.localdomain": {
                    "A": ["127.0.0.44"],
                    "TXT": [mock_bimi_txt_default],
                },
                "nondefault._bimi.test.localdomain": {
                    "A": ["127.0.0.44"],
                    "TXT": [mock_bimi_txt_nondefault],
                },
                "_bimi.default._bimi.test.localdomain": {
                    "A": ["127.0.0.44"],
                    "TXT": [mock_bimi_txt_default],
                },
                "_bimi.nondefault._bimi.test.localdomain": {
                    "A": ["127.0.0.44"],
                    "TXT": [mock_bimi_txt_default],
                },
                "default._bimi.default._bimi.test.localdomain": {
                    "A": ["127.0.0.44"],
                    "TXT": [mock_bimi_txt_default],
                },
                "nondefault._bimi.nondefault._bimi.test.localdomain": {
                    "A": ["127.0.0.44"],
                    "TXT": [mock_bimi_txt_nondefault],
                },
            }
        )

    def check(self, module_test, events):
        assert any(
            e.type == "RAW_DNS_RECORD"
            and e.data["host"] == "default._bimi.test.localdomain"
            and e.data["type"] == "TXT"
            and e.data["answer"] == raw_bimi_txt_default
            for e in events
        ), "Failed to emit RAW_DNS_RECORD"
        assert any(
            e.type == "RAW_DNS_RECORD"
            and e.data["host"] == "nondefault._bimi.test.localdomain"
            and e.data["type"] == "TXT"
            and e.data["answer"] == raw_bimi_txt_nondefault
            for e in events
        ), "Failed to emit RAW_DNS_RECORD"

        assert any(e.type == "DNS_NAME" and e.data == "bimi.test.localdomain" for e in events), (
            "Failed to emit DNS_NAME"
        )

        # This should be filtered by a default BBOT configuration
        assert not any(str(e.data) == "https://nondefault.thirdparty.tld/brand/logo.svg" for e in events)

        # This should not be filtered by a default BBOT configuration
        assert any(
            e.type == "URL_UNVERIFIED" and e.url == "https://bimi.test.localdomain/certificate.pem" for e in events
        ), "Failed to emit URL_UNVERIFIED"

        # These should be filtered simply due to distance
        assert not any(str(e.data) == "https://nondefault.thirdparty.tld/brand/logo.svg" for e in events)
        assert not any(str(e.data) == "https://nondefault.thirdparty.tld/certificate.pem" for e in events)

        # These should have been filtered via filter_event()
        assert not any(
            e.type == "RAW_DNS_RECORD" and e.data["host"] == "default._bimi.default._bimi.test.localdomain"
            for e in events
        ), "Unwanted recursion occurring"
        assert not any(
            e.type == "RAW_DNS_RECORD" and e.data["host"] == "nondefault._bimi.nondefault._bimi.test.localdomain"
            for e in events
        ), "Unwanted recursion occurring"
        assert not any(
            e.type == "RAW_DNS_RECORD" and e.data["host"] == "nondefault._bimi.default._bimi.test.localdomain"
            for e in events
        ), "Unwanted recursion occurring"
        assert not any(
            e.type == "RAW_DNS_RECORD" and e.data["host"] == "default._bimi.nondefault._bimi.test.localdomain"
            for e in events
        ), "Unwanted recursion occurring"
