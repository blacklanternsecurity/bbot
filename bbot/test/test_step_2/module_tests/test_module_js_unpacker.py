import json

from .base import ModuleTestBase


# -- Realistic packed/obfuscated JS fixtures --

SOURCE_MAP_JS = r"""!function(e,t){"object"==typeof exports&&"object"==typeof module?module.exports=t():"function"==typeof define&&define.amd?define([],t):"object"==typeof exports?exports.MyLib=t():e.MyLib=t()}(self,(function(){return(()=>{"use strict";var e={d:(t,n)=>{for(var r in n)e.o(n,r)&&!e.o(t,r)&&Object.defineProperty(t,r,{enumerable:!0,get:n[r]})},o:(e,t)=>Object.prototype.hasOwnProperty.call(e,t)};var t={};e.d(t,{default:()=>n});const n={init:function(e){this.config=Object.assign({debug:!1,endpoint:"/api/v2/collect"},e)},track:function(e,t){this.queue.push({event:e,properties:t||{},timestamp:Date.now()})}};return t})()}));
//# sourceMappingURL=my-lib.min.js.map"""

SOURCE_MAP_JSON = json.dumps(
    {
        "version": 3,
        "file": "my-lib.min.js",
        "sources": ["src/index.js", "src/tracker.js"],
        "sourcesContent": [
            'import { Tracker } from "./tracker";\nconst tracker = new Tracker({\n  endpoint: "http://127.0.0.1:8888/analytics/collect",\n  batchSize: 10,\n});\ntracker.init();\n',
            'export class Tracker {\n  constructor(config) {\n    this.endpoint = config.endpoint || "http://127.0.0.1:8888/fallback/collect";\n  }\n  flush() {\n    navigator.sendBeacon(this.endpoint, JSON.stringify({ events: this.queue }));\n  }\n}\n',
        ],
        "mappings": "AAAA",
    }
)

# Dean Edwards packed JS. The payload "u://s:8888/p/o.j" decodes via keyword
# substitution to "http://127.0.0.1:8888/hidden/tracker.js":
#   u(pos30)=http, s(pos28)=127.0.0.1, p(pos25)=hidden, o(pos24)=tracker, j(pos19)=js
# The ":8888/" and "." separators stay literal (not word chars).
DEAN_EDWARDS_JS = r"""eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};if(!''.replace(/^/,String)){while(c--){d[e(c)]=k[c]||e(c)}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('v 9=["\\x6F\\x6E\\x6C\\x6F\\x61\\x64"];b[9[0]]=f(){v 3=h[9[1]]("r");3[9[2]]="";v 7=h[9[5]](9[4]);7[9[3]]="u://s:8888/p/o.j";h[9[6]][9[7]](7)};',32,32,'|||el|||||||_0x1a2b|||||function||document||js|analytics|cdn|static|loader|tracker|hidden|com|main|127.0.0.1|cdn2|http|var'.split('|'),0,{}))"""

# obfuscator.io sample with a hidden API URL in the string array
OBFUSCATOR_IO_JS = r"""var _0x4e2f=['querySelector','addEventListener','click','getAttribute','data-target','getElementById','style','display','none','block','http://127.0.0.1:8888/tracker/events','POST','Content-Type','application/json','fetch','method','DOMContentLoaded','complete','readyState'];(function(_0x2a8c13,_0x4e2f6d){var _0x3b1c04=function(_0x5d6e2a){while(--_0x5d6e2a){_0x2a8c13['push'](_0x2a8c13['shift']());}};_0x3b1c04(++_0x4e2f6d);}(_0x4e2f,0x7b));var _0x3b1c=function(_0x2a8c13,_0x4e2f6d){_0x2a8c13=_0x2a8c13-0x0;var _0x3b1c04=_0x4e2f[_0x2a8c13];return _0x3b1c04;};(function(){document[_0x3b1c('0x0')]('.nav-toggle')[_0x3b1c('0x1')](_0x3b1c('0x2'),function(){var _0x2ce9=this[_0x3b1c('0x3')](_0x3b1c('0x4'));document[_0x3b1c('0x5')](_0x2ce9)[_0x3b1c('0x6')][_0x3b1c('0x7')]=_0x3b1c('0x9');_0x3b1c('0xe')(_0x3b1c('0xa'),{_0x3b1c('0xf'):_0x3b1c('0xb')});});})();"""

NEXTJS_MANIFEST_JS = """self.__BUILD_MANIFEST=function(s,c,a,e,d,b,f,g){return{__rewrites:{afterFiles:[],beforeFiles:[],fallback:[]},"/":["static/chunks/pages/index-8a3b2c1d.js"],"/about":[s,"static/chunks/pages/about-f4e7d6a2.js"],"/blog":[s,c,"static/chunks/pages/blog-1b9e3c5a.js"],"/blog/[slug]":[s,c,a,"static/chunks/pages/blog/[slug]-7d2f4e8b.js"],"/contact":[s,"static/chunks/pages/contact-3a6c9d1e.js"],"/dashboard":[s,c,e,"static/chunks/pages/dashboard-5e8b2f7d.js"],"/dashboard/settings":[s,c,e,d,"static/chunks/pages/dashboard/settings-9c4a1e6f.js"],"/api/health":[],"/_error":["static/chunks/pages/_error-2b5d8f3a.js"],sortedPages:["/","/about","/api/health","/blog","/blog/[slug]","/contact","/dashboard","/dashboard/settings","/_error"]}}("static/chunks/438-a2c7e4d1b3f89056.js","static/chunks/291-d5f8a1c3e7b24690.js","static/chunks/834-b7e2d4f6a8c31095.js","static/chunks/612-c9a3e5d7f1b48062.js","static/chunks/157-e1d3f5a7c9b20648.js"),self.__BUILD_MANIFEST_CB&&self.__BUILD_MANIFEST_CB();"""

NEXTJS_HTML = """<!DOCTYPE html><html><head><meta charSet="utf-8"/><title>Blog</title></head><body><div id="__next"><main><h1>Blog</h1></main></div><script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"posts":[{"id":"a1b2c3","title":"Getting Started","slug":"getting-started"}],"totalPages":5,"currentPage":1},"__N_SSP":true},"page":"/blog","query":{},"buildId":"xK7rT2mN9pQ4wE6y","isFallback":false,"gssp":true,"scriptLoader":[]}</script></body></html>"""

WEBPACK_JS = """(window.webpackJsonp=window.webpackJsonp||[]).push([[3],{147:function(e,t,n){"use strict";n.r(t);var r=n(0),o=n(1),i=n(12);var u=function(){function e(t){this.baseUrl=t.baseUrl||"http://127.0.0.1:8888/api/v1",this.headers={"Content-Type":"application/json",Accept:"application/json"},t.apiKey&&(this.headers["X-API-Key"]=t.apiKey)}var t;return t=e,(n=[{key:"request",value:function(e,t,n){var r=this;return fetch(this.baseUrl+t,Object.assign({},{method:e,headers:this.headers}))}}])&&l(t.prototype,n),e}();t.default=u},12:function(e,t,n){"use strict";n.d(t,"a",(function(){return r}));var r=function(e){return"string"==typeof e&&e.length>0}}}]);"""

# Plain JS with no packing
CLEAN_JS = """(function(){"use strict";var app={init:function(){document.addEventListener("DOMContentLoaded",function(){console.log("ready")})},render:function(el,data){el.innerHTML=data.map(function(item){return"<div>"+item.name+"</div>"}).join("")}};app.init()})();"""


class TestJsUnpacker(ModuleTestBase):
    module_name = "js_unpacker"
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["http", "excavate", "js_unpacker"]
    config_overrides = {"web": {"spider_distance": 2, "spider_depth": 4, "spider_links_per_page": 25}}

    async def setup_after_prep(self, module_test):
        index_html = """<html><head>
        <script src="/js/packed.js"></script>
        <script src="/js/bundle.js"></script>
        <script src="/js/obfuscated.js"></script>
        <script src="/js/lib.min.js"></script>
        <script src="/_next/static/xK7rT2mN9pQ4wE6y/_buildManifest.js"></script>
        <script src="/js/clean.js"></script>
        <a href="/blog">Blog</a>
        </head><body>ok</body></html>"""
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/"},
            respond_args={"response_data": index_html},
        )
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/js/packed.js"},
            respond_args={"response_data": DEAN_EDWARDS_JS, "content_type": "application/javascript"},
        )
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/js/bundle.js"},
            respond_args={"response_data": WEBPACK_JS, "content_type": "application/javascript"},
        )
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/js/obfuscated.js"},
            respond_args={"response_data": OBFUSCATOR_IO_JS, "content_type": "application/javascript"},
        )
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/js/lib.min.js"},
            respond_args={"response_data": SOURCE_MAP_JS, "content_type": "application/javascript"},
        )
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/js/my-lib.min.js.map"},
            respond_args={"response_data": SOURCE_MAP_JSON, "content_type": "application/json"},
        )
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/_next/static/xK7rT2mN9pQ4wE6y/_buildManifest.js"},
            respond_args={"response_data": NEXTJS_MANIFEST_JS, "content_type": "application/javascript"},
        )
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/js/clean.js"},
            respond_args={"response_data": CLEAN_JS, "content_type": "application/javascript"},
        )
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/blog"},
            respond_args={"response_data": NEXTJS_HTML, "content_type": "text/html"},
        )

    def check(self, module_test, events):
        detections = module_test.module.detections
        detected_names = {name for name, url in detections}
        detected_urls = {url for name, url in detections}

        # -- Detection assertions --
        assert "dean-edwards" in detected_names, "Dean Edwards packer not detected"
        assert "webpack" in detected_names, "Webpack bundle not detected"
        assert "obfuscator-io" in detected_names, "obfuscator.io not detected"
        assert "source-map" in detected_names, "Source map not detected"
        assert "nextjs" in detected_names, "Next.js manifest not detected"
        assert not any("clean.js" in u for u in detected_urls), "Clean JS should not trigger detection"

        # Next.js should detect both _buildManifest.js and __NEXT_DATA__ in HTML
        nextjs_urls = {url for name, url in detections if name == "nextjs"}
        assert any("blog" in u for u in nextjs_urls), "Next.js __NEXT_DATA__ not detected in /blog HTML"
        assert any("_buildManifest.js" in u for u in nextjs_urls), "Next.js _buildManifest not detected"

        # -- End-to-end extraction assertions --
        # All hidden URLs point to 127.0.0.1:8888 so they stay in-scope
        url_events = {e.data.get("url", e.data) for e in events if e.type == "URL_UNVERIFIED"}

        # Source map: excavate should find URLs from the original source
        assert any("/analytics/collect" in str(u) for u in url_events), (
            "Source map: excavate didn't find /analytics/collect"
        )
        assert any("/fallback/collect" in str(u) for u in url_events), (
            "Source map: excavate didn't find /fallback/collect"
        )

        # Dean Edwards: excavate should find the hidden URL after unpacking
        assert any("/hidden/tracker" in str(u) for u in url_events), (
            "Dean Edwards: excavate didn't find /hidden/tracker"
        )

        # obfuscator.io: excavate should find the API endpoint after deobfuscation
        assert any("/tracker/events" in str(u) for u in url_events), (
            "obfuscator.io: excavate didn't find /tracker/events"
        )

        # Webpack: excavate should find the API base URL
        assert any("/api/v1" in str(u) for u in url_events), "Webpack: excavate didn't find /api/v1"

        # Next.js: should emit route URLs
        assert any("/about" in str(u) for u in url_events), "Next.js: didn't emit /about route"
        assert any("/contact" in str(u) for u in url_events), "Next.js: didn't emit /contact route"
        assert any("/dashboard" in str(u) for u in url_events), "Next.js: didn't emit /dashboard route"


# JWT signed with "keyboard cat" (in badsecrets wordlist), packed with Dean Edwards
PACKED_JWT_JS = r"""eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};if(!''.replace(/^/,String)){while(c--)d[e(c)]=k[c]||e(c);k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--)if(k[c])p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c]);return p}('0 1 = 1 || {};\n1.2 = "/3/4";\n1.5 = "6.7.8";\n1.9 = a() {\n    0 b = c.d("b");\n    b.e = "f";\n    g.h("9 i");\n};\nc.j("k", 1.9);',22,21,'var|Config|apiBase|api|v2|platformToken|eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9|eyJzdWIiOiJzdmMtdGVzdCIsImlhdCI6MTcxODAwMDAwMCwiZXhwIjoxNzQ5NTM2MDAwLCJyb2xlIjoiYWRtaW4ifQ|G3x7IT4oTz4LNpphnOEcFEuztBOE_zBSs1owpqDluFU|init|function|status|document|getElementById|textContent|connected|console|log|complete|addEventListener|DOMContentLoaded'.split('|'),0,{}))"""

VULN_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdmMtdGVzdCIsImlhdCI6MTcxODAwMDAwMCwiZXhwIjoxNzQ5NTM2MDAwLCJyb2xlIjoiYWRtaW4ifQ.G3x7IT4oTz4LNpphnOEcFEuztBOE_zBSs1owpqDluFU"


class TestJsUnpackerBadsecretsChain(ModuleTestBase):
    """js_unpacker -> excavate -> badsecrets: a packed JWT with a weak secret should produce a HIGH finding."""

    module_name = "js_unpacker"
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["http", "excavate", "js_unpacker", "badsecrets"]

    async def setup_after_prep(self, module_test):
        page_html = f"<html><head><script>{PACKED_JWT_JS}</script></head><body>ok</body></html>"
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/"},
            respond_args={"response_data": page_html},
        )

    def check(self, module_test, events):
        badsecrets_finding = any(
            e.type == "FINDING" and "keyboard cat" in e.data["description"] and VULN_JWT in e.data["description"]
            for e in events
        )
        assert badsecrets_finding, "badsecrets should find 'keyboard cat' in unpacked JWT"

        excavate_jwt = any(
            e.type == "FINDING"
            and "JWT" in e.data["description"]
            and "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" in e.data["description"]
            for e in events
        )
        assert excavate_jwt, "excavate should extract JWT from unpacked response"
