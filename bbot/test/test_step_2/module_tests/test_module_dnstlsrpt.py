from .base import ModuleTestBase

raw_smtp_tls_txt = '"v=TLSRPTv1; rua=mailto:tlsrpt@sub.blacklanternsecurity.notreal,mailto:test@on.thirdparty.com, https://tlspost.example.com;"'


class TestDNSTLSRPT(ModuleTestBase):
    targets = ["blacklanternsecurity.notreal"]
    modules_overrides = ["dnstlsrpt", "speculate"]
    config_overrides = {"modules": {"dnstlsrpt": {"emit_raw_dns_records": True}}, "scope": {"report_distance": 1}}

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "blacklanternsecurity.notreal": {
                    "A": ["127.0.0.11"],
                },
                "_tls.blacklanternsecurity.notreal": {
                    "A": ["127.0.0.22"],
                },
                "_smtp._tls.blacklanternsecurity.notreal": {
                    "A": ["127.0.0.33"],
                    "TXT": [raw_smtp_tls_txt],
                },
                "_tls._smtp._tls.blacklanternsecurity.notreal": {
                    "A": ["127.0.0.44"],
                },
                "_smtp._tls._smtp._tls.blacklanternsecurity.notreal": {
                    "TXT": [raw_smtp_tls_txt],
                },
                "sub.blacklanternsecurity.notreal": {
                    "A": ["127.0.0.55"],
                },
            }
        )

    def check(self, module_test, events):
        assert any(e.type == "RAW_DNS_RECORD" and e.data["answer"] == raw_smtp_tls_txt for e in events), (
            "Failed to emit RAW_DNS_RECORD"
        )
        assert any(e.type == "DNS_NAME" and e.data == "sub.blacklanternsecurity.notreal" for e in events), (
            "Failed to detect sub-domain"
        )
        assert any(
            e.type == "EMAIL_ADDRESS" and e.data == "tlsrpt@sub.blacklanternsecurity.notreal" for e in events
        ), "Failed to detect email address"
        assert any(e.type == "EMAIL_ADDRESS" and e.data == "test@on.thirdparty.com" for e in events), (
            "Failed to detect third party email address"
        )
        assert any(e.type == "URL_UNVERIFIED" and e.data == "https://tlspost.example.com/" for e in events), (
            "Failed to detect third party URL"
        )


class TestDNSTLSRPTRecursiveRecursion(TestDNSTLSRPT):
    config_overrides = {
        "scope": {"report_distance": 1},
        "modules": {"dnstlsrpt": {"emit_raw_dns_records": True}},
    }

    def check(self, module_test, events):
        assert not any(
            e.type == "RAW_DNS_RECORD" and e.data["host"] == "_mta-sts._mta-sts.blacklanternsecurity.notreal"
            for e in events
        ), "Unwanted recursion occurring"
