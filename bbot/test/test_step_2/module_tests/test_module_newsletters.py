from .base import ModuleTestBase

# import logging


class TestNewsletters(ModuleTestBase):
    found_tgt = "http://127.0.0.1:8888/found"
    missing_tgt = "http://127.0.0.1:8888/missing"
    targets = [found_tgt, missing_tgt]
    modules_overrides = ["speculate", "httpx", "newsletters"]

    html_with_newsletter = """
    <input aria-required="true"
    class="form-input form-input-text required"
    data-at="form-email"
    data-describedby="form-validation-error-box-element-5"
    data-label-inside="Enter your email"
    id="field-5f329905b4bfe1027b44513f94b50363-0"
    name="Enter your email"
    placeholder="Enter your email"
    required=""
    title="Enter your email"
    type="email" value=""/>
    """

    html_without_newsletter = """
    <div>
    <h1>Example Domain</h1>
    <p>This domain is for use in illustrative examples in documents. You may use this
    domain in literature without prior coordination or asking for permission.</p>
    <p><a href="https://www.iana.org/domains/example">More information...</a></p>
    </div>
    """

    async def setup_after_prep(self, module_test):
        request_args = {"uri": "/found", "headers": {"test": "header"}}
        respond_args = {"response_data": self.html_with_newsletter}
        module_test.set_expect_requests(request_args, respond_args)
        request_args = {"uri": "/missing", "headers": {"test": "header"}}
        respond_args = {"response_data": self.html_without_newsletter}
        module_test.set_expect_requests(request_args, respond_args)

    def check(self, module_test, events):
        found = False
        missing = True
        for event in events:
            # self.log.info(f"event type: {event.type}")
            if event.type == "FINDING":
                # self.log.info(f"event data: {event.data}")
                # Verify Positive Result
                if event.data["url"] == self.found_tgt:
                    found = True
                # Verify Negative Result (should skip this statement if correct)
                elif event.data["url"] == self.missing_tgt:
                    missing = False
        assert found, "NEWSLETTER 'Found' Error - Expect status of True but got False"
        assert missing, "NEWSLETTER 'Missing' Error - Expect status of True but got False"
