from ..bbot_fixtures import *  # noqa: F401

from bbot.modules.templates.browser_vulns import browser_vulns, js_tokens, normalize_code, script_key


def test_normalize_code():
    # the same code with different data
    assert normalize_code('HT={"items":[1,2,3],"name":"Adelaide","on":!0};') == normalize_code(
        'HT={"items":[4,5,6,7,8],"name":"Perth","on":!1};'
    )
    assert normalize_code("HT = {a: [1, 2, {b: 'c'}], d: -1};") == "HT = _ ;"
    assert normalize_code("var n = 1;") == normalize_code("var n = 2;")
    assert normalize_code("x.replace(/\\/l\\/adelaide/, '')") == normalize_code("x.replace(/\\/l\\/perth/, '')")
    long_text = "a string longer than the strings kept in code"
    assert normalize_code(f'el.title = "{long_text}";') == normalize_code(
        'el.title = "another string, also long enough";'
    )
    # whitespace and comments
    assert normalize_code("a = b; // a comment\n/* another */ c(d);") == normalize_code("a=b;c(d);")

    # different code
    assert normalize_code("el.innerHTML = location.hash;") != normalize_code("el.textContent = location.hash;")
    # short strings in code are kept, so reading a different parameter or element is different code
    assert normalize_code('params.get("q")') != normalize_code('params.get("id")')
    # an array or object holding code isn't data
    assert normalize_code("f({a: b})") != normalize_code("f({a: c})")
    assert normalize_code("x = [a, b];") != normalize_code("x = [a, c];")
    # the code inside a template literal is kept, its text isn't
    assert normalize_code("el.innerHTML = `<b>${location.hash}</b>`;") == "el . innerHTML = _ location . hash _ ;"
    assert normalize_code("`<i>${a}</i>`") == normalize_code("`<b>${a}</b>`")
    assert normalize_code("`${a}`") != normalize_code("`${b}`")
    assert normalize_code("`${ {a: 1}.a }`") == normalize_code("`${ {a: 2}.a }`")


def test_js_tokens():
    # a slash after a value divides; elsewhere it starts a regex
    assert js_tokens("a / b / c") == [("word", "a"), ("punct", "/"), ("word", "b"), ("punct", "/"), ("word", "c")]
    assert js_tokens("x = /a\\/b[/]/g") == [("word", "x"), ("punct", "="), ("literal", "/a\\/b[/]/g")]
    assert js_tokens("return /x/.test(s)")[1] == ("literal", "/x/")
    # input that isn't JavaScript still tokenizes
    assert js_tokens('"unterminated\n`also unterminated ${')[0] == ("other", '"')


def test_script_key():
    # query values and fragments are dropped, parameter names kept
    assert (
        script_key("https://ads.example.com/conv/?random=1794663852574&cv=11#x")
        == "https://ads.example.com/conv/?random&cv"
    )
    assert script_key("https://example.com/app.js") == "https://example.com/app.js"
    assert script_key("https://example.com/app.js?v=1") != script_key("https://example.com/app.js?build=1")


PAGE = """<html><body>
<h1>{title}</h1>
<button onclick="track(HT.city, 1)">book</button>
<script>HT = {{"city": "{title}", "hotels": [{hotels}]}};</script>
<script>document.getElementById("x").innerHTML = HT.city;</script>
<script type="application/json">{{"city": "{title}"}}</script>
<script src="/app.js?v=1"></script>
</body></html>"""


def test_code_fingerprint(bbot_scanner):
    module = browser_vulns(bbot_scanner())
    scripts = ["https://example.com/app.js", "https://ads.example.com/conv/?random=1794663852574"]
    adelaide = module.code_fingerprint(PAGE.format(title="Adelaide", hotels="1, 2"), scripts)

    # pages from the same template share a fingerprint, however their content differs
    perth_scripts = ["https://ads.example.com/conv/?random=1794663856335", "https://example.com/app.js"]
    assert module.code_fingerprint(PAGE.format(title="Perth", hotels="3, 4, 5"), perth_scripts) == adelaide

    # a different script, a script fewer, or different code doesn't
    page = PAGE.format(title="Adelaide", hotels="1, 2")
    assert module.code_fingerprint(page, scripts + ["https://example.com/map.js"]) != adelaide
    assert module.code_fingerprint(page, scripts[:1]) != adelaide
    assert module.code_fingerprint(page.replace("innerHTML", "textContent"), scripts) != adelaide
    assert module.code_fingerprint(page.replace("onclick", "onmouseover"), scripts) != adelaide
    assert module.code_fingerprint(page.replace("<h1>", '<a href="javascript:go()">'), scripts) != adelaide
