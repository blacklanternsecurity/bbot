from .base import ModuleTestBase


class TestBadSecrets(ModuleTestBase):
    targets = [
        "http://127.0.0.1:8888/",
        "http://127.0.0.1:8888/test.aspx",
        "http://127.0.0.1:8888/cookie.aspx",
        "http://127.0.0.1:8888/cookie2.aspx",
    ]

    sample_viewstate = """
    <form method="post" action="./query.aspx" id="form1">
<div class="aspNetHidden">
<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="rJdyYspajyiWEjvZ/SMXsU/1Q6Dp1XZ/19fZCABpGqWu+s7F1F/JT1s9mP9ED44fMkninhDc8eIq7IzSllZeJ9JVUME41i8ozheGunVSaESf4nBu" />
</div>

<div class="aspNetHidden">

    <input type="hidden" name="__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="EDD8C9AE" />
    <input type="hidden" name="__VIEWSTATEENCRYPTED" id="__VIEWSTATEENCRYPTED" value="" />
</div>
    </form>
</body>
</html>
"""

    sample_viewstate_notvuln = """
    <form method="post" action="./query.aspx" id="form1">
<div class="aspNetHidden">
<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="AAAAYspajyiWEjvZ/SMXsU/1Q6Dp1XZ/19fZCABpGqWu+s7F1F/JT1s9mP9ED44fMkninhDc8eIq7IzSllZeJ9JVUME41i8ozheGunVSaESfAAAA" />
</div>

<div class="aspNetHidden">

    <input type="hidden" name="__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="EDD8C9AE" />
    <input type="hidden" name="__VIEWSTATEENCRYPTED" id="__VIEWSTATEENCRYPTED" value="" />
</div>
    </form>
</body>
</html>
"""

    modules_overrides = ["badsecrets", "httpx"]

    async def setup_after_prep(self, module_test):
        expect_args = {"uri": "/test.aspx"}
        respond_args = {"response_data": self.sample_viewstate}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        respond_args = {"response_data": self.sample_viewstate_notvuln}
        module_test.set_expect_requests(respond_args=respond_args)

        expect_args = {"uri": "/cookie.aspx"}
        respond_args = {
            "response_data": "<html><body><p>JWT Cookie Test</p></body></html>",
            "headers": {
                "set-cookie": "vulnjwt=eyJhbGciOiJIUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.ovqRikAo_0kKJ0GVrAwQlezymxrLGjcEiW_s3UJMMCo; secure"
            },
        }
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"uri": "/cookie2.aspx"}
        respond_args = {
            "response_data": "<html><body><p>Express Cookie Test</p></body></html>",
            "headers": {
                "set-cookie": "connect.sid=s%3A8FnPwdeM9kdGTZlWvdaVtQ0S1BCOhY5G.qys7H2oGSLLdRsEq7sqh7btOohHsaRKqyjV4LiVnBvc; Path=/; Expires=Wed, 05 Apr 2023 04:47:29 GMT; HttpOnly"
            },
        }
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        SecretFound = False
        IdentifyOnly = False
        CookieBasedDetection = False
        CookieBasedDetection_2 = False

        for e in events:
            if (
                e.type == "VULNERABILITY"
                and "Known Secret Found." in e.data["description"]
                and "validationKey: 0F97BAE23F6F36801ABDB5F145124E00A6F795A97093D778EE5CD24F35B78B6FC4C0D0D4420657689C4F321F8596B59E83F02E296E970C4DEAD2DFE226294979 validationAlgo: SHA1 encryptionKey: 8CCFBC5B7589DD37DC3B4A885376D7480A69645DAEEC74F418B4877BEC008156 encryptionAlgo: AES"
                in e.data["description"]
            ):
                SecretFound = True

            if (
                e.type == "FINDING"
                and "AAAAYspajyiWEjvZ/SMXsU/1Q6Dp1XZ/19fZCABpGqWu+s7F1F/JT1s9mP9ED44fMkninhDc8eIq7IzSllZeJ9JVUME41i8ozheGunVSaESfAAAA"
                in e.data["description"]
            ):
                IdentifyOnly = True

            if (
                e.type == "VULNERABILITY"
                and "1234" in e.data["description"]
                and "eyJhbGciOiJIUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.ovqRikAo_0kKJ0GVrAwQlezymxrLGjcEiW_s3UJMMCo"
                in e.data["description"]
            ):
                CookieBasedDetection = True

            if (
                e.type == "VULNERABILITY"
                and "keyboard cat" in e.data["description"]
                and "s%3A8FnPwdeM9kdGTZlWvdaVtQ0S1BCOhY5G.qys7H2oGSLLdRsEq7sqh7btOohHsaRKqyjV4LiVnBvc"
                in e.data["description"]
            ):
                CookieBasedDetection_2 = True

        assert SecretFound, "No secret found"
        assert IdentifyOnly, "No crypto product identified"
        assert CookieBasedDetection, "No JWT cookie detected"
        assert CookieBasedDetection_2, "No Express.js cookie detected"
