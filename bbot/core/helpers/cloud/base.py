import re
import logging

log = logging.getLogger("bbot.helpers.cloud.provider")


class BaseCloudProvider:
    domains = []
    regexes = {}

    def __init__(self, parent_helper):
        self.parent_helper = parent_helper
        self.name = str(self.__class__.__name__).lower()
        self.dummy_module = self.parent_helper._make_dummy_module(f"{self.name}_cloud", _type="scan")
        self.bucket_name_regex = re.compile("^" + self.bucket_name_regex + "$", re.I)
        self.signatures = {}
        self.domain_regexes = []
        for domain in self.domains:
            self.domain_regexes.append(re.compile(r"^(?:[\w\-]+\.)*" + rf"{re.escape(domain)}$"))
        for event_type, regexes in self.regexes.items():
            self.signatures[event_type] = [re.compile(r, re.I) for r in regexes]

    @property
    def base_tags(self):
        return {f"cloud-{self.name}"}

    def excavate(self, event, http_body):
        base_kwargs = dict(source=event, tags=self.base_tags)

        # check for buckets in HTTP responses
        for event_type, sigs in self.signatures.items():
            found = set()
            for sig in sigs:
                for match in sig.findall(http_body):
                    kwargs = dict(base_kwargs)
                    kwargs["event_type"] = event_type
                    if not match in found:
                        found.add(match)
                        if event_type == "STORAGE_BUCKET":
                            self.emit_bucket(match, **kwargs)
                        else:
                            self.emit_event(**kwargs)

    def speculate(self, event):
        base_kwargs = dict(source=event, tags=self.base_tags)

        if event.type.startswith("DNS_NAME"):
            # check for DNS_NAMEs that are buckets
            for event_type, sigs in self.signatures.items():
                found = set()
                for sig in sigs:
                    match = sig.match(event.data)
                    if match:
                        kwargs = dict(base_kwargs)
                        kwargs["event_type"] = event_type
                        if not event.data in found:
                            found.add(event.data)
                            if event_type == "STORAGE_BUCKET":
                                self.emit_bucket(match.groups(), **kwargs)
                            else:
                                self.emit_event(**kwargs)

    def emit_bucket(self, match, **kwargs):
        bucket_name, bucket_domain = match
        kwargs["data"] = {"name": bucket_name, "url": f"https://{bucket_name}.{bucket_domain}"}
        self.emit_event(**kwargs)

    def emit_event(self, *args, **kwargs):
        excavate_module = self.parent_helper.scan.modules.get("excavate", None)
        if excavate_module:
            event = self.dummy_module.make_event(*args, **kwargs)
            if event:
                excavate_module.emit_event(event)

    def is_valid_bucket(self, bucket_name):
        return self.bucket_name_regex.match(bucket_name)

    def tag_event(self, event):
        # tag the event if
        if event.host:
            # its host directly matches this cloud provider's domains
            if isinstance(event.host, str) and self.domain_match(event.host):
                event.tags.update(self.base_tags)
                # tag as buckets, etc.
                for event_type, sigs in self.signatures.items():
                    for sig in sigs:
                        if sig.match(event.host):
                            event.add_tag(f"cloud-{event_type}")
            else:
                # or it has a CNAME that matches this cloud provider's domains
                for rh in event.resolved_hosts:
                    if not self.parent_helper.is_ip(rh) and self.domain_match(rh):
                        event.tags.update(self.base_tags)

    def domain_match(self, s):
        for r in self.domain_regexes:
            if r.match(s):
                return True
        return False
