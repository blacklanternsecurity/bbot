from .test_module_excavate import TestExcavateParameterExtraction


class TestWebParameters(TestExcavateParameterExtraction):
    modules_overrides = ["excavate", "http", "web_parameters"]

    def check(self, module_test, events):
        parameters_file = module_test.scan.home / "web_parameters.txt"
        with open(parameters_file) as f:
            data = f.read()

        for name in (
            "age",
            "blog-post-author-display",
            "csrf",
            "fit",
            "id",
            "jqueryget",
            "jquerypost",
            "q1",
            "q2",
            "q3",
            "q4",
            "q5",
            "size",
            "test",
        ):
            assert name in data, f"missing parameter: {name}"


class TestWebParameters_include_count(TestWebParameters):
    config_overrides = {
        "web": {"spider_distance": 1, "spider_depth": 1},
        "modules": {"web_parameters": {"include_count": True}},
    }

    def check(self, module_test, events):
        parameters_file = module_test.scan.home / "web_parameters.txt"
        with open(parameters_file) as f:
            data = f.read()

        # "test" is the custom http_headers value the test scan injects; each
        # HTTP_RESPONSE re-emits it as a HEADER WEB_PARAMETER, so it shows 3.
        # Every other param is extracted once per unique (type, name, url).
        for expected in (
            "3\ttest",
            "1\tage",
            "1\tblog-post-author-display",
            "1\tcsrf",
            "1\tfit",
            "1\tid",
            "1\tjqueryget",
            "1\tjquerypost",
            "1\tq1",
            "1\tq2",
            "1\tq3",
            "1\tq4",
            "1\tq5",
            "1\tsize",
        ):
            assert expected in data, f"missing line: {expected!r}"
