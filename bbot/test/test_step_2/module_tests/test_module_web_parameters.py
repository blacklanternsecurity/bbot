from .test_module_excavate import TestExcavateParameterExtraction


class TestWebParameters(TestExcavateParameterExtraction):
    modules_overrides = ["excavate", "httpx", "web_parameters"]

    def check(self, module_test, events):
        parameters_file = module_test.scan.home / "web_parameters.txt"
        with open(parameters_file) as f:
            data = f.read()

            assert "age" in data
            assert "fit" in data
            assert "id" in data
            assert "jqueryget" in data
            assert "jquerypost" in data
            assert "size" in data

            # after lightfuzz is merged uncomment these additional parameters
            # assert "blog-post-author-display" in data
            # assert "csrf" in data
            # assert "q1" in data
            # assert "q2" in data
            # assert "q3" in data
            # assert "test" in data


class TestWebParameters_include_count(TestWebParameters):
    config_overrides = {
        "web": {"spider_distance": 1, "spider_depth": 1},
        "modules": {"web_parameters": {"include_count": True}},
    }

    def check(self, module_test, events):
        parameters_file = module_test.scan.home / "web_parameters.txt"
        with open(parameters_file) as f:
            data = f.read()
            assert "2\tq" in data
            assert "1\tage" in data
            assert "1\tfit" in data
            assert "1\tid" in data
            assert "1\tjqueryget" in data
            assert "1\tjquerypost" in data
            assert "1\tsize" in data

            # after lightfuzz is merged, these will be the correct parameters to check

            # assert "3\ttest" in data
            # assert "2\tblog-post-author-display" in data
            # assert "2\tcsrf" in data
            # assert "2\tq2" in data
            # assert "1\tage" in data
            # assert "1\tfit" in data
            # assert "1\tid" in data
            # assert "1\tjqueryget" in data
            # assert "1\tjquerypost" in data
            # assert "1\tq1" in data
            # assert "1\tq3" in data
            # assert "1\tsize" in data
