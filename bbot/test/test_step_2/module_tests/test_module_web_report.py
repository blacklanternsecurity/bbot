from .base import ModuleTestBase


class TestWebReport(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "wappalyzer", "badsecrets", "web_report", "secretsdb"]

    async def setup_before_prep(self, module_test):
        # secretsdb --> FINDING
        # wappalyzer --> TECHNOLOGY
        # badsecrets --> VULNERABILITY
        respond_args = {"response_data": web_body}
        module_test.set_expect_requests(respond_args=respond_args)

    def check(self, module_test, events):
        report_file = module_test.scan.home / "web_report.html"
        with open(report_file) as f:
            report_content = f.read()
        assert "<li>[CRITICAL] Known Secret Found" in report_content
        assert (
            """<h3>URL</h3>
<ul>
<li><strong>http://127.0.0.1:8888/</strong>"""
            in report_content
        )
        assert """Possible secret (Asymmetric Private Key)""" in report_content
        assert "<h3>TECHNOLOGY</h3>" in report_content
        assert "<p>flask</p>" in report_content


web_body = """
<html>
<body>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Open+Sans+Condensed:wght@700&family=Open+Sans:ital,wght@0,400;0,600;0,700;0,800;1,400&display=swap" rel="stylesheet">
    <form method="post" action="./query.aspx" id="form1">
<div class="aspNetHidden">
<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="rJdyYspajyiWEjvZ/SMXsU/1Q6Dp1XZ/19fZCABpGqWu+s7F1F/JT1s9mP9ED44fMkninhDc8eIq7IzSllZeJ9JVUME41i8ozheGunVSaESf4nBu" />
</div>

<div class="aspNetHidden">

    <input type="hidden" name="__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="EDD8C9AE" />
    <input type="hidden" name="__VIEWSTATEENCRYPTED" id="__VIEWSTATEENCRYPTED" value="" />
</div>
    </form>
    <p>-----BEGIN PGP PRIVATE KEY BLOCK-----</p>
</body>
</html>
"""
