# adopted from https://github.com/bugcrowd/HUNT

import re
from bbot.modules.base import BaseModule


hunt_param_dict = {
    "Command Injection": [
        "daemon",
        "host",
        "upload",
        "dir",
        "execute",
        "download",
        "log",
        "ip",
        "cli",
        "cmd",
        "exec",
        "command",
        "func",
        "code",
        "update",
        "shell",
        "eval",
    ],
    "Debug": [
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
    "Directory Traversal": ["entry", "download", "attachment", "basepath", "path", "file", "source", "dest"],
    "Local File Include": [
        "file",
        "document",
        "folder",
        "root",
        "path",
        "pg",
        "style",
        "pdf",
        "template",
        "php_path",
        "doc",
        "lang",
        "include",
        "img",
        "view",
        "layout",
        "export",
        "log",
        "configFile",
        "stylesheet",
        "configFileUrl",
    ],
    "Insecure Direct Object Reference": [
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
        "docId",
        "accountId",
        "customerId",
        "reportId",
        "jobId",
        "sessionId",
        "api_key",
        "instance",
        "identifier",
        "access",
    ],
    "SQL Injection": [
        "id",
        "" "select",
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
        "limit",
        "offset",
        "item",
        "input",
        "date",
        "value",
        "orderBy",
        "groupBy",
        "pageNum",
        "pageSize",
        "tag",
        "author",
        "postId",
        "parentId",
        "d",
    ],
    "Server-side Request Forgery": [
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
        "proxy",
        "target",
        "server",
        "domain",
        "connect",
        "fetch",
        "apiEndpoint",
    ],
    "Server-Side Template Injection": [
        "template",
        "preview",
        "id",
        "view",
        "activity",
        "name",
        "content",
        "redirect",
        "expression",
        "statement",
        "tpl",
        "render",
        "format",
        "engine",
    ],
    "XML external entity injection": [
        "xml",
        "dtd",
        "xsd",
        "xmlDoc",
        "xmlData",
        "entityType",
        "entity",
        "xmlUrl",
        "schema",
        "xmlFile",
        "xmlPath",
        "xmlSource",
        "xmlEndpoint",
        "xslt",
        "xmlConfig",
        "xmlCallback",
        "attributeName",
        "wsdl",
        "xmlDocUrl",
    ],
    "Insecure Cryptography": [
        "encrypted",
        "cipher",
        "iv",
        "checksum",
        "hash",
        "salt",
        "hmac",
        "secret",
        "key",
        "signatureAlgorithm",
        "keyId",
        "sharedSecret",
        "privateKeyId",
        "privateKey",
        "publicKey",
        "publicKeyId",
        "encryptedData",
        "encryptedMessage",
        "encryptedPayload",
        "encryptedFile",
        "cipherText",
        "cipherAlgorithm",
        "keySize",
        "keyPair",
        "keyDerivation",
        "encryptionMethod",
        "decryptionKey",
    ],
    "Unsafe Deserialization": [
        "serialized",
        "object",
        "dataObject",
        "serialization",
        "payload",
        "encoded",
        "marshalled",
        "pickled",
        "jsonData",
        "state",
        "sessionData",
        "cache",
        "tokenData",
        "serializedSession",
        "objectState",
        "jsonDataPayload",
    ],
}


class hunt(BaseModule):
    input_tag_regex = re.compile(r"<input.+?name=[\"\'](\w+)[\"\']")
    jquery_get_regex = re.compile(r"url:\s?[\"\'].+?\?(\w+)=")
    jquery_post_regex = re.compile(r"\$.post\([\'\"].+[\'\"].+\{(.+)\}")
    a_tag_regex = re.compile(r"<a\s+(?:[^>]*?\s+)?href=(?:[\"\'](.+\?.+?))[\"\'].+[>\s]")

    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["FINDING"]
    flags = ["active", "safe", "web-basic", "web-thorough"]
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
