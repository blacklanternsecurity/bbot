from .base import ModuleTestBase, tempwordlist


class TestVirtualhost(ModuleTestBase):
    targets = ["http://localhost:8888", "secret.localhost"]
    modules_overrides = ["httpx", "virtualhost"]
    test_wordlist = ["11111111", "admin", "cloud", "junkword1", "zzzjunkword2"]
    config_overrides = {
        "modules": {
            "virtualhost": {
                "wordlist": tempwordlist(test_wordlist),
            }
        }
    }

    async def setup_after_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/", "headers": {"Host": "admin.localhost:8888"}}
        respond_args = {"response_data": "Alive virtualhost admin"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/", "headers": {"Host": "cloud.localhost:8888"}}
        respond_args = {"response_data": "Alive virtualhost cloud"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/", "headers": {"Host": "q-cloud.localhost:8888"}}
        respond_args = {"response_data": "Alive virtualhost q-cloud"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/", "headers": {"Host": "secret.localhost:8888"}}
        respond_args = {"response_data": "Alive virtualhost secret"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/", "headers": {"Host": "host.docker.internal"}}
        respond_args = {"response_data": "Alive virtualhost host.docker.internal"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "alive"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        basic_detection = False
        mutaton_of_detected = False
        basehost_mutation = False
        special_virtualhost_list = False
        wordcloud_detection = False

        for e in events:
            if e.type == "VIRTUAL_HOST":
                if e.data["virtual_host"] == "admin":
                    basic_detection = True
                if e.data["virtual_host"] == "cloud":
                    mutaton_of_detected = True
                if e.data["virtual_host"] == "q-cloud":
                    basehost_mutation = True
                if e.data["virtual_host"] == "host.docker.internal":
                    special_virtualhost_list = True
                if e.data["virtual_host"] == "secret":
                    wordcloud_detection = True

        assert basic_detection
        assert mutaton_of_detected
        assert basehost_mutation
        assert special_virtualhost_list
        assert wordcloud_detection
