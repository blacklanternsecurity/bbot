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
    print(r"<input.+?name=[\"\'](\w+)[\"\']")
    input_tag_regex = re.compile(r"<input.+?name=[\"\'](\w+)[\"\']")
    jquery_get_regex = re.compile(r"url:\s?[\"\'].+?\?(\w+)=")
    jquery_post_regex = re.compile(r"\$.post\([\'\"].+[\'\"].+\{(.+)\}")
    a_tag_regex = re.compile(r"<a\s+(?:[^>]*?\s+)?href=(?:[\"\'].+\?)(.+)[\"\']>")

    flags = ["active", "safe"]
    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["FINDING"]
    # accept all events regardless of scope distance
    scope_distance_modifier = None

    def extract_params(self, body):

        # check for input tags
        input_tag = re.findall(self.input_tag_regex, body)

        for i in input_tag:
            self.debug(f"FOUND PARAM ({i}) IN INPUT TAGS")
            yield i

        # check for jquery get parameters
        jquery_get = re.findall(self.jquery_get_regex, body)

        for i in jquery_get:
            self.debug(f"FOUND PARAM ({i}) IN JQUERY GET PARAMS")
            yield i

        # check for jquery post parameters

        jquery_post = re.findall(self.jquery_post_regex, body)
        if jquery_post:
            for i in jquery_post:
                for x in i.split(","):
                    s = x.split(":")[0].rstrip()
                    self.debug(f"FOUND PARAM ({s}) IN A JQUERY POST PARAMS")
                    yield s

        a_tag = re.findall(self.a_tag_regex, body)
        if a_tag:
            for i in a_tag:
                for x in i.split("&"):
                    s = x.split("=")[0]

                    self.debug(f"FOUND PARAM ({s}) IN A TAG GET PARAMS")
                    yield s

    def handle_event(self, event):
        self.hugeinfo(event.data.get("url"))
        body = event.data.get("response-body", "")
        for p in self.extract_params(body):
            for k in hunt_param_dict.keys():
                if p.lower() in hunt_param_dict[k]:
                    self.emit_event(
                        f"Found potential {k.upper()} parameter [{p}] in URL [{event.data.get('url')}]",
                        "FINDING",
                        event,
                    )
