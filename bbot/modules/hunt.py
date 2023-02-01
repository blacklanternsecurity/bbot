# adopted from https://github.com/bugcrowd/HUNT

import re
from bbot.modules.base import BaseModule


hunt_param_dict = {
    "cmdi": ["daemon", "host", "upload", "dir", "execute", "download", "log", "ip", "cli", "cmd"],
    "debug": [
        "access",
        "admin",
        "dbg",
        "debug",
        "edit",
        "grant",
        "test",
        "alter",
        "clone",
        "create",
        "delete",
        "disable",
        "enable",
        "exec",
        "execute",
        "load",
        "make",
        "modify",
        "rename",
        "reset",
        "shell",
        "toggle",
        "adm",
        "root",
        "cfg",
        "config",
    ],
    "lfi": ["file", "document", "folder", "root", "path", "pg", "style", "pdf", "template", "php_path", "doc"],
    "idor": [
        "id",
        "user",
        "account",
        "number",
        "order",
        "no",
        "doc",
        "key",
        "email",
        "group",
        "profile",
        "edit",
        "report",
    ],
    "sqli": [
        "id",
        "select",
        "report",
        "role",
        "update",
        "query",
        "user",
        "name",
        "sort",
        "where",
        "search",
        "params",
        "category",
        "process",
        "row",
        "view",
        "table",
        "from",
        "sel",
        "results",
        "sleep",
        "fetch",
        "order",
        "keyword",
        "column",
        "field",
        "delete",
        "string",
        "number",
        "filter",
    ],
    "ssrf": [
        "dest",
        "redirect",
        "uri",
        "path",
        "continue",
        "url",
        "window",
        "next",
        "data",
        "reference",
        "site",
        "html",
        "val",
        "validate",
        "domain",
        "callback",
        "return",
        "page",
        "feed",
        "host",
        "port",
        "to",
        "out",
        "view",
        "dir",
        "show",
        "navigation",
        "open",
    ],
    "ssti": ["template", "preview", "id", "view", "activity", "name", "content", "redirect"],
}


class hunt(BaseModule):
    input_tag_regex = re.compile(r"<input.+?name=[\"\'](\w+)[\"\']")
    jquery_get_regex = re.compile(r"url:\s?[\"\'].+?\?(\w+)=")
    jquery_post_regex = re.compile(r"\$.post\([\'\"].+[\'\"].+\{(.+)\}")
    a_tag_regex = re.compile(r"<a\s+(?:[^>]*?\s+)?href=(?:[\"\'](.+\?.+?))[\"\'].+[>\s]")

    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["FINDING"]
    flags = ["active", "safe", "web-advanced"]
    meta = {"description": "Watch for commonly-exploitable HTTP parameters"}
    # accept all events regardless of scope distance
    scope_distance_modifier = None

    def extract_params(self, body):
        # check for input tags
        input_tag = self.input_tag_regex.findall(body)

        for i in input_tag:
            self.debug(f"FOUND PARAM ({i}) IN INPUT TAGS")
            yield i

        # check for jquery get parameters
        jquery_get = self.jquery_get_regex.findall(body)

        for i in jquery_get:
            self.debug(f"FOUND PARAM ({i}) IN JQUERY GET PARAMS")
            yield i

        # check for jquery post parameters
        jquery_post = self.jquery_post_regex.findall(body)
        if jquery_post:
            for i in jquery_post:
                for x in i.split(","):
                    s = x.split(":")[0].rstrip()
                    self.debug(f"FOUND PARAM ({s}) IN A JQUERY POST PARAMS")
                    yield s

        a_tag = self.a_tag_regex.findall(body)
        if a_tag:
            for url in a_tag:
                if url.startswith("http"):
                    url_parsed = self.helpers.parse_url(url)
                    if not self.scan.in_scope(url_parsed.netloc):
                        self.debug(f"Skipping checking for parameters because URL ({url}) is not in scope")
                        continue
                    i = url_parsed.query.split("&")
                else:
                    i = url.split("?")[1].split("&")
                for x in i:
                    s = x.split("=")[0]

                    self.debug(f"FOUND PARAM ({s}) IN A TAG GET PARAMS")
                    yield s

    def handle_event(self, event):
        body = event.data.get("body", "")
        for p in self.extract_params(body):
            for k in hunt_param_dict.keys():
                if p.lower() in hunt_param_dict[k]:
                    description = f"Found potential {k.upper()} parameter [{p}]"
                    data = {"host": str(event.host), "description": description}
                    url = event.data.get("url", "")
                    if url:
                        data["url"] = url
                    self.emit_event(data, "FINDING", event)
