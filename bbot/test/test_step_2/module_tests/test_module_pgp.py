from .base import ModuleTestBase


class TestPGP(ModuleTestBase):
    web_body = """<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd" >
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<title>Search results for 'blacklanternsecurity.com'</title>
<meta http-equiv="Content-Type" content="text/html;charset=utf-8" />
<link href='/assets/css/pks.min.css' rel='stylesheet' type='text/css'>
<style type="text/css">

 .uid { color: green; text-decoration: underline; }
 .warn { color: red; font-weight: bold; }

</style></head><body><h1>Search results for 'blacklanternsecurity.com'</h1><pre>Type bits/keyID            cr. time   exp time   key expir
</pre>


<hr /><pre><strong>pub</strong> <a href="/pks/lookup?op=get&search=0xd4e98af823deadbeef">eddsa263/0xd4e98af823deadbeef</a> 2022-09-14T15:11:31Z

<strong>uid</strong> <span class="uid">Asdf &lt;asdf@blacklanternsecurity.com&gt;</span>
sig  sig  <a href="/pks/lookup?op=get&search=0xd4e98af823deadbeef">0xd4e98af823deadbeef</a> 2022-09-14T15:11:31Z 2024-09-14T17:00:00Z ____________________ <a href="/pks/lookup?op=vindex&search=0xd4e98af823deadbeef">[selfsig]</a>

</pre>
</body></html>"""

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://keyserver.ubuntu.com/pks/lookup?fingerprint=on&op=vindex&search=blacklanternsecurity.com",
            text=self.web_body,
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf@blacklanternsecurity.com" for e in events), "Failed to detect email"
