from .base import ModuleTestBase


class TestWebReport(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "wappalyzer", "badsecrets", "web_report", "trufflehog"]
    config_overrides = {"modules": {"trufflehog": {"only_verified": False}}}

    async def setup_before_prep(self, module_test):
        # trufflehog --> FINDING
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
        assert """Possible Secret Found. Detector Type: [PrivateKey]""" in report_content
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
    <p>-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAOBY2pd9PSQvuxqu
WXFNVgILTWuUc721Wc2sFNvp4beowhUe1lfxaq5ZfCJcz7z4QsqFhOeks69O9UIb
oiOTDocPDog9PHO8yZXopHm0StFZvSjjKSNuFvy/WopPTGpxUZ5boCaF1CXumY7W
FL+jIap5faimLL9prIwaQKBwv80lAgMBAAECgYEAxvpHtgCgD849tqZYMgOTevCn
U/kwxltoMOClB39icNA+gxj8prc6FTTMwnVq0oGmS5UskX8k1yHCqUV1AvRU9o+q
I8L8a3F3TQKQieI/YjiUNK8A87bKkaiN65ooOnhT+I3ZjZMPR5YEyycimMp22jsv
LyX/35J/wf1rNiBs/YECQQDvtxgmMhE+PeajXqw1w2C3Jds27hI3RPDnamEyWr/L
KkSplbKTF6FuFDYOFdJNPrfxm1tx2MZ2cBfs+h/GnCJVAkEA75Z9w7q8obbqGBHW
9bpuFvLjW7bbqO7HBuXYX9zQcZL6GSArFP0ba5lhgH1qsVQfxVWVyiV9/chme7xc
ljfvkQJBAJ7MpSPQcRnRefNp6R0ok+5gFqt55PlWI1y6XS81bO7Szm+laooE0n0Q
yIpmLE3dqY9VgquVlkupkD/9poU0s40CQD118ZVAVht1/N9n1Cj9RjiE3mYspnTT
rCLM25Db6Gz6M0Y2xlaAB4S2uBhqE/Chj/TjW6WbsJJl0kRzsZynhMECQFYKiM1C
T4LB26ynW00VE8z4tEWSoYt4/Vn/5wFhalVjzoSJ8Hm2qZiObRYLQ1m0X4KnkShk
Gnl54dJHT+EhlfY=
-----END PRIVATE KEY-----</p>
</body>
</html>
"""
