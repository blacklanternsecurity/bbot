from .base import ModuleTestBase, tempwordlist


class TestVhost(ModuleTestBase):
    targets = ["http://localhost:8888", "secret.localhost"]
    modules_overrides = ["httpx", "vhost"]
    test_wordlist = ["11111111", "admin", "cloud", "junkword1", "zzzjunkword2"]
    config_overrides = {
        "modules": {
            "vhost": {
                "wordlist": tempwordlist(test_wordlist),
            }
        }
    }

    async def setup_after_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/", "headers": {"Host": "admin.localhost:8888"}}
        respond_args = {"response_data": "Alive vhost admin"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/", "headers": {"Host": "cloud.localhost:8888"}}
        respond_args = {"response_data": "Alive vhost cloud"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/", "headers": {"Host": "q-cloud.localhost:8888"}}
        respond_args = {"response_data": "Alive vhost q-cloud"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/", "headers": {"Host": "secret.localhost:8888"}}
        respond_args = {"response_data": "Alive vhost secret"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/", "headers": {"Host": "host.docker.internal"}}
        respond_args = {"response_data": "Alive vhost host.docker.internal"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "alive"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        basic_detection = False
        mutaton_of_detected = False
        basehost_mutation = False
        special_vhost_list = False
        wordcloud_detection = False

        for e in events:
            if e.type == "VHOST":
                if e.data["vhost"] == "admin":
                    basic_detection = True
                if e.data["vhost"] == "cloud":
                    mutaton_of_detected = True
                if e.data["vhost"] == "q-cloud":
                    basehost_mutation = True
                if e.data["vhost"] == "host.docker.internal":
                    special_vhost_list = True
                if e.data["vhost"] == "secret":
                    wordcloud_detection = True

        assert basic_detection
        assert mutaton_of_detected
        assert basehost_mutation
        assert special_vhost_list
        assert wordcloud_detection
