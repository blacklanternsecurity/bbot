import json
import logging
import ipaddress
from typing import Optional
from datetime import datetime
from contextlib import suppress
from pydantic import BaseModel, validator
from threading import Event as ThreadingEvent

from .helpers import *
from bbot.core.errors import *
from bbot.core.helpers import (
    extract_words,
    split_host_port,
    host_in_host,
    is_domain,
    is_subdomain,
    is_ip,
    domain_stem,
    make_netloc,
    make_ip_type,
    smart_decode,
    get_file_extension,
    validators,
)


log = logging.getLogger("bbot.core.event")


class BaseEvent:

    # Exclude from output modules
    _omit = False
    # Priority, 1-5, lower numbers == higher priority
    _priority = 3
    # Disables certain data validations
    _dummy = False
    # Data validation, if data is a dictionary
    _data_validator = None

    def __init__(
        self,
        data,
        event_type=None,
        source=None,
        module=None,
        scan=None,
        tags=None,
        confidence=100,
        _dummy=False,
        _internal=None,
    ):

        self._id = None
        self._hash = None
        self.__host = None
        self._port = None
        self.__words = None
        self._made_internal = False
        # whether to force-send to output modules
        self._force_output = False

        self.timestamp = datetime.utcnow()

        if tags is None:
            tags = set()

        self._data = None
        self.type = event_type
        self.tags = set(tags)
        self.confidence = int(confidence)

        # for creating one-off events without enforcing source requirement
        self._dummy = _dummy
        self._internal = False

        self.module = module
        self.scan = scan
        if (not self.scan) and (not self._dummy):
            raise ValidationError(f"Must specify scan")

        # check type blacklist
        if self.scan is not None:
            omit_event_types = self.scan.config.get("omit_event_types", [])
            if omit_event_types and self.type in omit_event_types:
                self._omit = True

        self._scope_distance = -1

        try:
            self.data = self._sanitize_data(data)
        except Exception as e:
            import traceback

            log.debug(traceback.format_exc())
            raise ValidationError(f'Error sanitizing event data "{data}" for type "{self.type}": {e}')

        if not self.data:
            raise ValidationError(f'Invalid event data "{data}" for type "{self.type}"')

        self._source = None
        self.source_id = None
        self.source = source
        if (not self.source) and (not self._dummy):
            raise ValidationError(f"Must specify event source")

        if not self._dummy:
            self._setup()

        # internal events are not ingested by output modules
        if not self._dummy:
            # removed this second part because it was making certain sslcert events internal
            if _internal:  # or source._internal:
                self.make_internal()

        self._resolved = ThreadingEvent()

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, data):
        self._hash = None
        self._id = None
        self.__host = None
        self._port = None
        self._data = data

    @property
    def host(self):
        """
        An abbreviated representation of the data that allows comparison with other events.
        For host types, this is a hostname.
        This allows comparison of an email or a URL with a domain, and vice versa
            bob@evilcorp.com        --> evilcorp.com
            https://evilcorp.com    --> evilcorp.com
            evilcorp.com:80         --> evilcorp.com

        For IP_* types, this is an instantiated object representing the event's data
        E.g. for IP_ADDRESS, it could be an ipaddress.IPv4Address() or IPv6Address() object
        """
        if self.__host is None:
            self.__host = self._host()
        return self.__host

    @property
    def port(self):
        self.host
        return self._port

    @property
    def host_stem(self):
        """
        An abbreviated representation of hostname that removes the TLD
            E.g. www.evilcorp.com --> www.evilcorp
        """
        if self.host and type(self.host) == str:
            return domain_stem(self.host)
        else:
            return f"{self.host}"

    @property
    def words(self):
        if self.__words is None:
            self.__words = set(self._words())
        return self.__words

    def _words(self):
        return set()

    @property
    def id(self):
        if self._id is None:
            self._id = make_event_id(self.data_id, self.type)
        return self._id

    @property
    def scope_distance(self):
        return self._scope_distance

    @scope_distance.setter
    def scope_distance(self, scope_distance):
        if scope_distance >= 0:
            new_scope_distance = None
            # ensure scope distance does not increase (only allow setting to smaller values)
            if self.scope_distance == -1:
                new_scope_distance = scope_distance
            else:
                new_scope_distance = min(self.scope_distance, scope_distance)
            self._scope_distance = new_scope_distance
            for t in list(self.tags):
                if t.startswith("distance-"):
                    self.tags.remove(t)
            self.tags.add(f"distance-{new_scope_distance}")

    @property
    def source(self):
        return self._source

    @source.setter
    def source(self, source):
        if is_event(source):
            self._source = source
            if source.scope_distance >= 0 and source != self:
                new_scope_distance = int(source.scope_distance)
                # only increment the scope distance if the host changes
                if not self.host == source.host:
                    new_scope_distance += 1
                self.scope_distance = new_scope_distance
            self.source_id = str(source.id)
        elif not self._dummy:
            log.warning(f"Tried to set invalid source on {self}: (got: {source})")

    def get_source(self):
        """
        Takes into account events with the _omit flag
        """
        if getattr(self.source, "_omit", False):
            return self.source.get_source()
        return self.source

    def make_internal(self):
        if not self._made_internal:
            self._internal = True
            self.tags.add("internal")
            self._made_internal = True

    def unmake_internal(self, set_scope_distance=None, force_output=False, emit_trail=True):
        source_trail = []
        if self._made_internal:
            if set_scope_distance is not None:
                self.scope_distance = set_scope_distance
            self._internal = False
            self.tags.remove("internal")
            if force_output:
                self._force_output = True
            self._made_internal = False

        if getattr(self.source, "_internal", False):
            source_scope_distance = None
            if set_scope_distance is not None:
                source_scope_distance = set_scope_distance + 1
            source_trail += self.source.unmake_internal(
                set_scope_distance=source_scope_distance, force_output=force_output
            )
            source_trail.append(self.source)

        if emit_trail and self.scan:
            for e in source_trail:
                self.scan.manager.emit_event(e, release=False)

        return source_trail

    def make_in_scope(self, set_scope_distance=0):
        source_trail = []
        # keep the event internal if the module requests so, unless it's a DNS_NAME
        if getattr(self.module, "_scope_shepherding", True) or self.type in ("DNS_NAME",):
            source_trail = self.unmake_internal(
                set_scope_distance=set_scope_distance, force_output=True, emit_trail=True
            )
        self.scope_distance = set_scope_distance
        if set_scope_distance == 0:
            self.tags.add("in-scope")
        return source_trail

    def _host(self):
        return ""

    def _sanitize_data(self, data):
        if self._data_validator is not None:
            if not isinstance(data, dict):
                raise ValidationError(f"data is not of type dict: {data}")
            data = self._data_validator(**data).dict()
        return self.sanitize_data(data)

    def sanitize_data(self, data):
        return data

    @property
    def data_human(self):
        return self._data_human()

    def _data_human(self):
        return str(self.data)

    @property
    def data_id(self):
        return self._data_id()

    def _data_id(self):
        return self.data

    @property
    def data_graph(self):
        return self._data_graph()

    def _data_graph(self):
        if type(self.data) in (list, dict):
            with suppress(Exception):
                return json.dumps(self.data, sort_keys=True)
        return smart_decode(self.data)

    def _setup(self):
        """
        Perform optional setup, e.g. adding custom tags
        """

    def __contains__(self, other):
        """
        Allows events to be compared using the "in" operator:
        E.g.:
            if some_event in other_event:
                ...
        """
        try:
            other = make_event(other, dummy=True)
        except ValidationError:
            return False
        # if hashes match
        if other == self:
            return True
        # if hosts match
        if self.host and other.host:
            if self.host == other.host:
                return True
            # hostnames and IPs
            return host_in_host(other.host, self.host)
        return False

    def json(self, mode="graph"):
        j = dict()
        for i in ("type", "id", "web_spider_distance"):
            v = getattr(self, i, "")
            if v:
                j.update({i: v})
        data_attr = getattr(self, f"data_{mode}", None)
        if data_attr is not None:
            j["data"] = data_attr
        else:
            j["data"] = smart_decode(self.data)
        j["scope_distance"] = self.scope_distance
        j["scan"] = self.scan.id
        j["timestamp"] = self.timestamp.timestamp()
        source = self.get_source()
        source_id = getattr(source, "id", "")
        if source_id:
            j["source"] = source_id
        if self.tags:
            j.update({"tags": list(self.tags)})
        if self.module:
            j.update({"module": str(self.module)})

        # normalize non-primitive python objects
        for k, v in list(j.items()):
            if k == "data":
                continue
            if type(v) not in (str, int, float, bool, list, type(None)):
                try:
                    j[k] = json.dumps(v, sort_keys=True)
                except Exception:
                    j[k] = smart_decode(v)
        return j

    @property
    def priority(self):
        self_priority = int(max(1, min(5, self._priority)))
        mod_priority = int(max(1, min(5, getattr(self.module, "priority", 1))))
        timestamp = self.timestamp.timestamp()
        return self_priority + mod_priority + (1 / timestamp)

    def __iter__(self):
        """
        For dict(event)
        """
        yield from self.json().items()

    def __lt__(self, other):
        """
        For queue sorting
        """
        return self.priority < int(getattr(other, "priority", 5))

    def __gt__(self, other):
        """
        For queue sorting
        """
        return self.priority > int(getattr(other, "priority", 5))

    def __eq__(self, other):
        try:
            other = make_event(other, dummy=True)
        except ValidationError:
            return False
        return hash(self) == hash(other)

    def __hash__(self):
        if self._hash is None:
            self._hash = hash(self.id)
        return self._hash

    def __str__(self):
        d = str(self.data)
        return f'{self.type}("{d[:50]}{("..." if len(d) > 50 else "")}", module={self.module}, tags={self.tags})'

    def __repr__(self):
        return str(self)


class DefaultEvent(BaseEvent):
    def sanitize_data(self, data):
        return data


class DictEvent(BaseEvent):
    def _data_human(self):
        return json.dumps(self.data, sort_keys=True)


class DictHostEvent(DictEvent):
    def _host(self):
        return make_ip_type(self.data["host"])


class CODE_REPOSITORY(DictHostEvent):
    class _data_validator(BaseModel):
        url: str
        _validate_url = validator("url", allow_reuse=True)(validators.validate_url)

    def _host(self):
        self.parsed = validators.validate_url_parsed(self.data["url"])
        return make_ip_type(self.parsed.hostname)

    def _data_graph(self):
        return self.data["url"]


class IP_ADDRESS(BaseEvent):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        ip = ipaddress.ip_address(self.data)
        self.tags.add(f"ipv{ip.version}")
        if ip.is_private:
            self.tags.add("private")

    def sanitize_data(self, data):
        return validators.validate_host(data)

    def _host(self):
        return ipaddress.ip_address(self.data)


class IP_RANGE(BaseEvent):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        net = ipaddress.ip_network(self.data, strict=False)
        self.tags.add(f"ipv{net.version}")

    def sanitize_data(self, data):
        return str(ipaddress.ip_network(str(data), strict=False))

    def _host(self):
        return ipaddress.ip_network(self.data)


class DNS_NAME(BaseEvent):
    _priority = 2

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if is_subdomain(self.data):
            self.tags.add("subdomain")
        elif is_domain(self.data):
            self.tags.add("domain")

    def sanitize_data(self, data):
        return validators.validate_host(data)

    def _host(self):
        return self.data

    def _words(self):
        stem = self.host_stem
        if "wildcard" in self.tags:
            stem = "".join(stem.split(".")[1:])
        return extract_words(self.host_stem)


class OPEN_TCP_PORT(BaseEvent):
    def sanitize_data(self, data):
        return validators.validate_open_port(data)

    def _host(self):
        host, self._port = split_host_port(self.data)
        return host

    def _words(self):
        if not is_ip(self.host):
            return extract_words(self.host_stem)
        return set()


class URL_UNVERIFIED(BaseEvent):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.web_spider_distance = getattr(self.source, "web_spider_distance", 0)

    def sanitize_data(self, data):
        self.parsed = validators.validate_url_parsed(data)

        # tag as dir or endpoint
        if str(self.parsed.path).endswith("/"):
            self.tags.add("dir")
        else:
            self.tags.add("endpoint")

        parsed_path_lower = str(self.parsed.path).lower()

        url_extension_blacklist = []
        url_extension_httpx_only = []
        scan = getattr(self, "scan", None)
        if scan is not None:
            url_extension_blacklist = [e.lower() for e in scan.config.get("url_extension_blacklist", [])]
            url_extension_httpx_only = [e.lower() for e in scan.config.get("url_extension_httpx_only", [])]

        extension = get_file_extension(parsed_path_lower)
        if extension:
            self.tags.add(f"extension-{extension}")
            if extension in url_extension_blacklist:
                self.tags.add("blacklisted")
            if extension in url_extension_httpx_only:
                self.tags.add("httpx-only")
                self._omit = True

        data = self.parsed.geturl()
        return data

    def with_port(self):
        netloc_with_port = make_netloc(self.host, self.port)
        return self.parsed._replace(netloc=netloc_with_port)

    def _words(self):
        first_elem = self.parsed.path.lstrip("/").split("/")[0]
        if not "." in first_elem:
            return extract_words(first_elem)
        return set()

    def _host(self):
        return make_ip_type(self.parsed.hostname)

    @property
    def port(self):
        if self.parsed.port is not None:
            return self.parsed.port
        elif self.parsed.scheme == "https":
            return 443
        elif self.parsed.scheme == "http":
            return 80


class URL(URL_UNVERIFIED):
    def sanitize_data(self, data):
        if not self._dummy and not any(t.startswith("status-") for t in self.tags):
            raise ValidationError(
                'Must specify HTTP status tag for URL event, e.g. "status-200". Use URL_UNVERIFIED if the URL is unvisited.'
            )
        return super().sanitize_data(data)


class URL_HINT(URL_UNVERIFIED):
    pass


class EMAIL_ADDRESS(BaseEvent):
    def sanitize_data(self, data):
        return validators.validate_email(data)

    def _host(self):
        data = str(self.data).split("@")[-1]
        host, self._port = split_host_port(data)
        return host

    def _words(self):
        return extract_words(self.host_stem)


class HTTP_RESPONSE(URL_UNVERIFIED, DictEvent):
    _priority = 2

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.web_spider_distance = getattr(self.source, "web_spider_distance", 0)
        if not str(self.data.get("status-code", 0)).startswith("3"):
            self.web_spider_distance += 1

    def sanitize_data(self, data):
        url = data.get("url", "")
        self.parsed = validators.validate_url_parsed(url)

        header_dict = {}
        for i in data.get("response-header", "").splitlines():
            if len(i) > 0 and ":" in i:
                k, v = i.split(":", 1)
                k = k.strip().lower()
                v = v.lstrip()
                header_dict[k] = v
        data["header-dict"] = header_dict
        return data

    def _words(self):
        return set()


class VULNERABILITY(DictHostEvent):
    _priority = 1

    def _sanitize_data(self, data):
        data = super()._sanitize_data(data)
        self.tags.add(data["severity"].lower())
        return data

    class _data_validator(BaseModel):
        host: str
        severity: str
        description: str
        url: Optional[str]
        _validate_host = validator("host", allow_reuse=True)(validators.validate_host)
        _validate_severity = validator("severity", allow_reuse=True)(validators.validate_severity)

    def _data_graph(self):
        return f'[{self.data["severity"]}] {self.data["description"]}'


class FINDING(DictHostEvent):
    _priority = 1

    class _data_validator(BaseModel):
        host: str
        description: str
        url: Optional[str]
        _validate_host = validator("host", allow_reuse=True)(validators.validate_host)

    def _data_graph(self):
        return self.data["description"]


class TECHNOLOGY(DictHostEvent):
    _priority = 2

    class _data_validator(BaseModel):
        host: str
        technology: str
        url: Optional[str]
        _validate_host = validator("host", allow_reuse=True)(validators.validate_host)

    def _data_graph(self):
        return self.data["technology"]


class VHOST(DictHostEvent):
    class _data_validator(BaseModel):
        host: str
        vhost: str
        url: Optional[str]
        _validate_host = validator("host", allow_reuse=True)(validators.validate_host)

    def _data_graph(self):
        return self.data["vhost"]


class PROTOCOL(DictHostEvent):
    class _data_validator(BaseModel):
        host: str
        protocol: str
        _validate_host = validator("host", allow_reuse=True)(validators.validate_open_port)

    def _host(self):
        host, self._port = split_host_port(self.data["host"])
        return host

    def _data_graph(self):
        return self.data["protocol"]


def make_event(
    data, event_type=None, source=None, module=None, scan=None, tags=None, confidence=100, dummy=False, internal=None
):
    """
    If data is already an event, simply return it
    """

    if is_event(data):
        if scan is not None and not data.scan:
            data.scan = scan
        if module is not None:
            data.module = module
        if source is not None:
            data.set_source(source)
        if internal == True and not data._made_internal:
            data.make_internal()
        event_type = data.type
        return data
    else:
        if event_type is None:
            event_type = get_event_type(data)
            if not dummy:
                log.debug(f'Autodetected event type "{event_type}" based on data: "{data}"')
        if event_type is None:
            raise ValidationError(f'Unable to autodetect event type from "{data}"')

        event_type = str(event_type).strip().upper()

        # Catch these common whoopsies

        # DNS_NAME <--> IP_ADDRESS confusion
        if event_type in ("DNS_NAME", "IP_ADDRESS"):
            try:
                data = validators.validate_host(data)
            except Exception as e:
                raise ValidationError(f'Error sanitizing event data "{data}" for type "{event_type}": {e}')
            data_is_ip = is_ip(data)
            if event_type == "DNS_NAME" and data_is_ip:
                event_type = "IP_ADDRESS"
            elif event_type == "IP_ADDRESS" and not data_is_ip:
                event_type = "DNS_NAME"

        # DNS_NAME <--> EMAIL_ADDRESS confusion
        if event_type in ("DNS_NAME", "EMAIL_ADDRESS"):
            data_is_email = validators.soft_validate(data, "email")
            if event_type == "DNS_NAME" and data_is_email:
                event_type = "EMAIL_ADDRESS"
            elif event_type == "EMAIL_ADDRESS" and not data_is_email:
                event_type = "DNS_NAME"

        event_class = globals().get(event_type, DefaultEvent)

        return event_class(
            data,
            event_type=event_type,
            source=source,
            module=module,
            scan=scan,
            tags=tags,
            confidence=confidence,
            _dummy=dummy,
            _internal=internal,
        )


def is_event(e):
    return BaseEvent in e.__class__.__mro__
