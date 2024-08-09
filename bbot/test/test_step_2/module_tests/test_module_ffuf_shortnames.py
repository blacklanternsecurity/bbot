from .base import ModuleTestBase, tempwordlist


class TestFFUFShortnames(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    test_wordlist = ["11111111", "administrator", "portal", "console", "junkword1", "zzzjunkword2", "directory"]
    config_overrides = {
        "modules": {
            "ffuf_shortnames": {
                "find_common_prefixes": True,
                "wordlist": tempwordlist(test_wordlist),
            }
        }
    }
    modules_overrides = ["ffuf_shortnames", "httpx"]

    async def setup_after_prep(self, module_test):
        module_test.httpserver.no_handler_status_code = 404

        seed_events = []
        parent_event = module_test.scan.make_event(
            "http://127.0.0.1:8888/",
            "URL",
            module_test.scan.root_event,
            module="httpx",
            tags=["status-200", "distance-0"],
        )
        seed_events.append(
            module_test.scan.make_event(
                "http://127.0.0.1:8888/ADMINI~1.ASP",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-file"],
            )
        )
        seed_events.append(
            module_test.scan.make_event(
                "http://127.0.0.1:8888/ADM_PO~1.ASP",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-file"],
            )
        )
        seed_events.append(
            module_test.scan.make_event(
                "http://127.0.0.1:8888/ABCZZZ~1.ASP",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-file"],
            )
        )
        seed_events.append(
            module_test.scan.make_event(
                "http://127.0.0.1:8888/ABCXXX~1.ASP",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-file"],
            )
        )
        seed_events.append(
            module_test.scan.make_event(
                "http://127.0.0.1:8888/ABCYYY~1.ASP",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-file"],
            )
        )
        seed_events.append(
            module_test.scan.make_event(
                "http://127.0.0.1:8888/ABCCON~1.ASP",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-file"],
            )
        )
        seed_events.append(
            module_test.scan.make_event(
                "http://127.0.0.1:8888/DIRECT~1",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-directory"],
            )
        )
        seed_events.append(
            module_test.scan.make_event(
                "http://127.0.0.1:8888/ADM_DI~1",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-directory"],
            )
        )
        seed_events.append(
            module_test.scan.make_event(
                "http://127.0.0.1:8888/XYZDIR~1",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-directory"],
            )
        )
        seed_events.append(
            module_test.scan.make_event(
                "http://127.0.0.1:8888/XYZAAA~1",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-directory"],
            )
        )
        seed_events.append(
            module_test.scan.make_event(
                "http://127.0.0.1:8888/XYZBBB~1",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-directory"],
            )
        )
        seed_events.append(
            module_test.scan.make_event(
                "http://127.0.0.1:8888/XYZCCC~1",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-directory"],
            )
        )
        seed_events.append(
            module_test.scan.make_event(
                "http://127.0.0.1:8888/SHORT~1.PL",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-file"],
            )
        )
        module_test.scan.target.seeds._events = set(seed_events)

        expect_args = {"method": "GET", "uri": "/administrator.aspx"}
        respond_args = {"response_data": "alive"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/adm_portal.aspx"}
        respond_args = {"response_data": "alive"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/abcconsole.aspx"}
        respond_args = {"response_data": "alive"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/directory/"}
        respond_args = {"response_data": "alive"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/adm_directory/"}
        respond_args = {"response_data": "alive"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/xyzdirectory/"}
        respond_args = {"response_data": "alive"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/short.pl"}
        respond_args = {"response_data": "alive"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        basic_detection = False
        directory_detection = False
        prefix_detection = False
        delimiter_detection = False
        directory_delimiter_detection = False
        prefix_delimiter_detection = False
        short_extensions_detection = False

        for e in events:
            if e.type == "URL_UNVERIFIED":
                if e.data == "http://127.0.0.1:8888/administrator.aspx":
                    basic_detection = True
                if e.data == "http://127.0.0.1:8888/directory/":
                    directory_detection = True
                if e.data == "http://127.0.0.1:8888/adm_portal.aspx":
                    prefix_detection = True
                if e.data == "http://127.0.0.1:8888/abcconsole.aspx":
                    delimiter_detection = True
                if e.data == "http://127.0.0.1:8888/abcconsole.aspx":
                    directory_delimiter_detection = True
                if e.data == "http://127.0.0.1:8888/xyzdirectory/":
                    prefix_delimiter_detection = True
                if e.data == "http://127.0.0.1:8888/short.pl":
                    short_extensions_detection = True

        assert basic_detection
        assert directory_detection
        assert prefix_detection
        assert delimiter_detection
        assert directory_delimiter_detection
        assert prefix_delimiter_detection
        assert short_extensions_detection
