from .base import ModuleTestBase

page1 = """

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
            "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<title>Parent domain: evilcorp.com</title>
<style type="text/css">
body {background: #dae5da; margin: 0; padding: 0; text-align: left; font-size: 10pt; font-style: normal; font-family: verdana, arial; color: #202020; height: 100%;  }
a:link { color: #2020ff; }
a:visited { color: #78208c; }
div.mid {background: repeat-y #8fb38f; min-height: 100%; height: 100%; }
div.header {background: repeat-y #8fb38f; }
div.footer {background: repeat-y #8fb38f; }
div.stripe1 {background: repeat-y #cadbca;}
div.stripe2 {background: repeat-y #bad1ba;}
div.stripe3 {background: repeat-y #abc7ab;}
div.stripe4 {background: repeat-y #9dbd9d;}
H1 {font-size: 18pt; font-style: normal; font-family: arial; color: #202020; margin: 5px 5px 5px; }
H2 {font-size: 12pt; font-style: normal; font-family: arial; color: #202020; margin: 5px 5px 5px; }
H3 {font-size: 12pt; font-style: normal; font-family: arial; color: #202020; margin: 5px 5px 5px; }
</style>
<META NAME="ROBOTS" CONTENT="NOARCHIVE">
</head>
<body>
<center>
<div class="header">
<img src="/i/sdlogonew2.jpg" alt="logo">
<br>
<div class="stripe4"><img src="/i/1x1.gif" alt="" width="100%" height=1></div>
<div class="stripe3"><img src="/i/1x1.gif" alt="" width="100%" height=1></div>
<div class="stripe2"><img src="/i/1x1.gif" alt="" width="100%" height=1></div>
<div class="stripe1"><img src="/i/1x1.gif" alt="" width="100%" height=1></div>
</div>
<br>
<table border=0 cellspacing=0 cellpadding=0 width=750>
<tr><td width=30><img src="/i/corner-nw-dae5da.png" alt="nw" width=30 height=30></td><td width=690 height=30 bgcolor="#ffffff"></td><td width=30><img src="/i/corner-ne-dae5da.png" alt="ne" width=30 height=30></td></tr>
<tr><td width=30 height="100%" bgcolor="#ffffff"></td>
<td bgcolor="#ffffff" width=690 align="left">
<h1>Parent domain: evilcorp.com</h1>
<br>
<font style="font-size: 9pt; font-style: normal; font-family: arial; color: #000000;">
<dd> <i>Displaying items 101 to 200, out of a total of 685</i>
<br>
<ol start=101>
<li> &nbsp; <a href="/site/asdf.evilcorp.com">http://asdf.evilcorp.com/</a><br>
<li> &nbsp; <a href="/site/zzzz.evilcorp.com">http://zzzz.evilcorp.com/</a><br>
</ol>
<a href="/parentdomain/evilcorp.com/101"><b>Show next 100 items</b></a><br>
</font>
</td>
<td width=30 height="100%" bgcolor="#ffffff"></td></tr>
<tr><td width=30><img src="/i/corner-sw-dae5da.png" alt="sw" width=30 height=30></td><td width=690 height=30 bgcolor="#ffffff"></td><td width=30><img src="/i/corner-se-dae5da.png" alt="se" width=30 height=30></td></tr>
</table>
<br>
<br>
<br>
</body>
</html>
"""

page2 = """

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
            "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<title>Parent domain: evilcorp.com</title>
<style type="text/css">
body {background: #dae5da; margin: 0; padding: 0; text-align: left; font-size: 10pt; font-style: normal; font-family: verdana, arial; color: #202020; height: 100%;  }
a:link { color: #2020ff; }
a:visited { color: #78208c; }
div.mid {background: repeat-y #8fb38f; min-height: 100%; height: 100%; }
div.header {background: repeat-y #8fb38f; }
div.footer {background: repeat-y #8fb38f; }
div.stripe1 {background: repeat-y #cadbca;}
div.stripe2 {background: repeat-y #bad1ba;}
div.stripe3 {background: repeat-y #abc7ab;}
div.stripe4 {background: repeat-y #9dbd9d;}
H1 {font-size: 18pt; font-style: normal; font-family: arial; color: #202020; margin: 5px 5px 5px; }
H2 {font-size: 12pt; font-style: normal; font-family: arial; color: #202020; margin: 5px 5px 5px; }
H3 {font-size: 12pt; font-style: normal; font-family: arial; color: #202020; margin: 5px 5px 5px; }
</style>
<META NAME="ROBOTS" CONTENT="NOARCHIVE">
</head>
<body>
<center>
<div class="header">
<img src="/i/sdlogonew2.jpg" alt="logo">
<br>
<div class="stripe4"><img src="/i/1x1.gif" alt="" width="100%" height=1></div>
<div class="stripe3"><img src="/i/1x1.gif" alt="" width="100%" height=1></div>
<div class="stripe2"><img src="/i/1x1.gif" alt="" width="100%" height=1></div>
<div class="stripe1"><img src="/i/1x1.gif" alt="" width="100%" height=1></div>
</div>
<br>
<table border=0 cellspacing=0 cellpadding=0 width=750>
<tr><td width=30><img src="/i/corner-nw-dae5da.png" alt="nw" width=30 height=30></td><td width=690 height=30 bgcolor="#ffffff"></td><td width=30><img src="/i/corner-ne-dae5da.png" alt="ne" width=30 height=30></td></tr>
<tr><td width=30 height="100%" bgcolor="#ffffff"></td>
<td bgcolor="#ffffff" width=690 align="left">
<h1>Parent domain: evilcorp.com</h1>
<br>
<font style="font-size: 9pt; font-style: normal; font-family: arial; color: #000000;">
<dd> <i>Displaying items 101 to 200, out of a total of 685</i>
<br>
<ol start=101>
<li> &nbsp; <a href="/site/xxxx.evilcorp.com">http://xxxx.evilcorp.com/</a><br>
<li> &nbsp; <a href="/site/ffff.evilcorp.com">http://ffff.evilcorp.com/</a><br>
</ol>
</font>
</td>
<td width=30 height="100%" bgcolor="#ffffff"></td></tr>
<tr><td width=30><img src="/i/corner-sw-dae5da.png" alt="sw" width=30 height=30></td><td width=690 height=30 bgcolor="#ffffff"></td><td width=30><img src="/i/corner-se-dae5da.png" alt="se" width=30 height=30></td></tr>
</table>
<br>
<br>
<br>
</body>
</html>
"""


class TestSitedossier(ModuleTestBase):
    targets = ["evilcorp.com"]

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "evilcorp.com": {"A": ["127.0.0.1"]},
                "asdf.evilcorp.com": {"A": ["127.0.0.1"]},
                "zzzz.evilcorp.com": {"A": ["127.0.0.1"]},
                "xxxx.evilcorp.com": {"A": ["127.0.0.1"]},
                "ffff.evilcorp.com": {"A": ["127.0.0.1"]},
            }
        )
        module_test.httpx_mock.add_response(
            url=f"http://www.sitedossier.com/parentdomain/evilcorp.com",
            text=page1,
        )
        module_test.httpx_mock.add_response(
            url=f"http://www.sitedossier.com/parentdomain/evilcorp.com/101",
            text=page2,
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.evilcorp.com" for e in events), "Failed to detect subdomain"
        assert any(e.data == "zzzz.evilcorp.com" for e in events), "Failed to detect subdomain"
        assert any(e.data == "xxxx.evilcorp.com" for e in events), "Failed to detect subdomain"
        assert any(e.data == "ffff.evilcorp.com" for e in events), "Failed to detect subdomain"
