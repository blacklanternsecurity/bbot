from .base import ModuleTestBase
from bbot.test.worker import HTTPSERVER_URL


class TestWebBruteShortnames(ModuleTestBase):
    targets = [HTTPSERVER_URL]
    module_name = "webbrute_shortnames"
    config_overrides = {
        "modules": {
            "webbrute_shortnames": {
                "find_common_prefixes": True,
                "find_subwords": True,
                "max_predictions": 250,
            }
        }
    }
    modules_overrides = ["webbrute_shortnames", "http"]

    async def setup_after_prep(self, module_test):
        module_test.httpserver.no_handler_status_code = 404

        seed_events = []
        parent_event = module_test.scan.make_event(
            f"{HTTPSERVER_URL}/",
            "URL",
            module_test.scan.root_event,
            module="http",
            tags=["status-200", "distance-0"],
        )
        seed_events.append(
            module_test.scan.make_event(
                f"{HTTPSERVER_URL}/ADMINI~1.ASP",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-endpoint"],
            )
        )
        seed_events.append(
            module_test.scan.make_event(
                f"{HTTPSERVER_URL}/ADM_PO~1.ASP",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-endpoint"],
            )
        )
        seed_events.append(
            module_test.scan.make_event(
                f"{HTTPSERVER_URL}/ABCZZZ~1.ASP",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-endpoint"],
            )
        )
        seed_events.append(
            module_test.scan.make_event(
                f"{HTTPSERVER_URL}/ABCXXX~1.ASP",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-endpoint"],
            )
        )
        seed_events.append(
            module_test.scan.make_event(
                f"{HTTPSERVER_URL}/ABCYYY~1.ASP",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-endpoint"],
            )
        )
        seed_events.append(
            module_test.scan.make_event(
                f"{HTTPSERVER_URL}/ABCCON~1.ASP",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-endpoint"],
            )
        )
        seed_events.append(
            module_test.scan.make_event(
                f"{HTTPSERVER_URL}/DIRECT~1",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-directory"],
            )
        )
        seed_events.append(
            module_test.scan.make_event(
                f"{HTTPSERVER_URL}/ADM_DI~1",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-directory"],
            )
        )
        seed_events.append(
            module_test.scan.make_event(
                f"{HTTPSERVER_URL}/XYZDIR~1",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-directory"],
            )
        )
        seed_events.append(
            module_test.scan.make_event(
                f"{HTTPSERVER_URL}/XYZAAA~1",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-directory"],
            )
        )
        seed_events.append(
            module_test.scan.make_event(
                f"{HTTPSERVER_URL}/XYZBBB~1",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-directory"],
            )
        )
        seed_events.append(
            module_test.scan.make_event(
                f"{HTTPSERVER_URL}/XYZCCC~1",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-directory"],
            )
        )
        seed_events.append(
            module_test.scan.make_event(
                f"{HTTPSERVER_URL}/SHORT~1.PL",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-endpoint"],
            )
        )

        seed_events.append(
            module_test.scan.make_event(
                f"{HTTPSERVER_URL}/newpro~1.asp",
                "URL_HINT",
                parent_event,
                module="iis_shortnames",
                tags=["shortname-endpoint"],
            )
        )
        for event in seed_events:
            await module_test.scan.ingress_module.incoming_event_queue.put(event)

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

        expect_args = {"method": "GET", "uri": "/newproxy.aspx"}
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
        subword_detection = False

        for e in events:
            if e.type == "URL_UNVERIFIED":
                if e.url == f"{HTTPSERVER_URL}/administrator.aspx":
                    basic_detection = True
                if e.url == f"{HTTPSERVER_URL}/directory/":
                    directory_detection = True
                if e.url == f"{HTTPSERVER_URL}/adm_portal.aspx":
                    prefix_detection = True
                if e.url == f"{HTTPSERVER_URL}/abcconsole.aspx":
                    delimiter_detection = True
                if e.url == f"{HTTPSERVER_URL}/adm_directory/":
                    directory_delimiter_detection = True
                if e.url == f"{HTTPSERVER_URL}/xyzdirectory/":
                    prefix_delimiter_detection = True
                if e.url == f"{HTTPSERVER_URL}/short.pl":
                    short_extensions_detection = True
                if e.url == f"{HTTPSERVER_URL}/newproxy.aspx":
                    subword_detection = True

        assert basic_detection
        assert directory_detection
        assert prefix_detection
        assert delimiter_detection
        assert directory_delimiter_detection
        assert prefix_delimiter_detection
        assert short_extensions_detection
        assert subword_detection
