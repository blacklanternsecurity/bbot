import re
import json
import asyncio
import logging
import ipaddress
import traceback
from copy import copy
from typing import Optional
from datetime import datetime
from contextlib import suppress
from urllib.parse import urljoin
from pydantic import BaseModel, field_validator

from .helpers import *
from bbot.core.errors import *
from bbot.core.helpers import (
    extract_words,
    get_file_extension,
    host_in_host,
    is_domain,
    is_subdomain,
    is_ip,
    is_ptr,
    is_uri,
    domain_stem,
    make_netloc,
    make_ip_type,
    recursive_decode,
    smart_decode,
    split_host_port,
    tagify,
    validators,
)


log = logging.getLogger("bbot.core.event")


class BaseEvent:
    """
    Represents a piece of data discovered during a BBOT scan.

    An Event contains various attributes that provide metadata about the discovered data.
    The attributes assist in understanding the context of the Event and facilitate further
    filtering and querying. Events are integral in the construction of visual graphs and
    are the cornerstone of data exchange between BBOT modules.

    You can inherit from this class when creating a new event type. However, it's not always
    necessary. You only need to subclass if you want to layer additional functionality on
    top of the base class.

    Attributes:
        type (str): Specifies the type of the event, e.g., `IP_ADDRESS`, `DNS_NAME`.
        id (str): A unique identifier for the event.
        data (str or dict): The main data for the event, e.g., a URL or IP address.
        data_graph (str): Representation of `self.data` for Neo4j graph nodes.
        data_human (str): Representation of `self.data` for human output.
        data_id (str): Representation of `self.data` used to calculate the event's ID (and ultimately its hash, which is used for deduplication)
        data_json (str): Representation of `self.data` to be used in JSON serialization.
        host (str, IPvXAddress, or IPvXNetwork): The associated IP address or hostname for the event
        host_stem (str): An abbreviated representation of hostname that removes the TLD, e.g. "www.evilcorp". Used by the word cloud.
        port (int or None): The port associated with the event, if applicable, else None.
        words (set): A list of relevant keywords extracted from the event. Used by the word cloud.
        scope_distance (int): Indicates how many hops the event is from the main scope; 0 means in-scope.
        web_spider_distance (int): The spider distance from the web root, specific to web crawling.
        scan (Scanner): The scan object that generated the event.
        timestamp (datetime.datetime): The time at which the data was discovered.
        resolved_hosts (list of str): List of hosts to which the event data resolves, applicable for URLs and DNS names.
        source (BaseEvent): The source event that led to the discovery of this event.
        source_id (str): The `id` attribute of the source event.
        tags (set of str): Descriptive tags for the event, e.g., `mx-record`, `in-scope`.
        module (BaseModule): The module that discovered the event.
        module_sequence (str): The sequence of modules that participated in the discovery.

    Examples:
        ```json
        {
            "type": "URL",
            "id": "URL:017ec8e5dc158c0fd46f07169f8577fb4b45e89a",
            "data": "http://www.blacklanternsecurity.com/",
            "web_spider_distance": 0,
            "scope_distance": 0,
            "scan": "SCAN:4d786912dbc97be199da13074699c318e2067a7f",
            "timestamp": 1688526222.723366,
            "resolved_hosts": ["185.199.108.153"],
            "source": "OPEN_TCP_PORT:cf7e6a937b161217eaed99f0c566eae045d094c7",
            "tags": ["in-scope", "distance-0", "dir", "ip-185-199-108-153", "status-301", "http-title-301-moved-permanently"],
            "module": "httpx",
            "module_sequence": "httpx"
        }
        ```
    """

    # Always emit this event type even if it's not in scope
    _always_emit = False
    # Always emit events with these tags even if they're not in scope
    _always_emit_tags = ["affiliate"]
    # Bypass scope checking and dns resolution, distribute immediately to modules
    # This is useful for "end-of-line" events like FINDING and VULNERABILITY
    _quick_emit = False
    # Whether this event has been retroactively marked as part of an important discovery chain
    _graph_important = False
    # Exclude from output modules
    _omit = False
    # Disables certain data validations
    _dummy = False
    # Data validation, if data is a dictionary
    _data_validator = None
    # Whether to increment scope distance if the child and parent hosts are the same
    _scope_distance_increment_same_host = False

    def __init__(
        self,
        data,
        event_type,
        source=None,
        module=None,
        scan=None,
        scans=None,
        tags=None,
        confidence=5,
        timestamp=None,
        _dummy=False,
        _internal=None,
    ):
        """
        Initializes an Event object with the given parameters.

        In most cases, you should use `make_event()` instead of instantiating this class directly.
        `make_event()` is much friendlier, and can auto-detect the event type for you.

        Attributes:
            data (str, dict): The primary data for the event.
            event_type (str, optional): Type of the event, e.g., 'IP_ADDRESS'.
            source (BaseEvent, optional): Source event that led to this event's discovery. Defaults to None.
            module (str, optional): Module that discovered the event. Defaults to None.
            scan (Scan, optional): BBOT Scan object. Required unless _dummy is True. Defaults to None.
            scans (list of Scan, optional): BBOT Scan objects, used primarily when unserializing an Event from the database. Defaults to None.
            tags (list of str, optional): Descriptive tags for the event. Defaults to None.
            confidence (int, optional): Confidence level for the event, on a scale of 1-10. Defaults to 5.
            timestamp (datetime, optional): Time of event discovery. Defaults to current UTC time.
            _dummy (bool, optional): If True, disables certain data validations. Defaults to False.
            _internal (Any, optional): If specified, makes the event internal. Defaults to None.

        Raises:
            ValidationError: If either `scan` or `source` are not specified and `_dummy` is False.
        """

        self._id = None
        self._hash = None
        self.__host = None
        self._port = None
        self.__words = None
        self._priority = None
        self._module_priority = None
        self._resolved_hosts = set()

        # keep track of whether this event has been recorded by the scan
        self._stats_recorded = False

        self.timestamp = datetime.utcnow()

        self._tags = set()
        if tags is not None:
            self._tags = set(tagify(s) for s in tags)

        self._data = None
        self._type = event_type
        self.confidence = int(confidence)

        # for creating one-off events without enforcing source requirement
        self._dummy = _dummy
        self._internal = False

        self.module = module
        # self.scan holds the instantiated scan object (for helpers, etc.)
        self.scan = scan
        if (not self.scan) and (not self._dummy):
            raise ValidationError(f"Must specify scan")
        # self.scans holds a list of scan IDs from scans that encountered this event
        self.scans = []
        if scans is not None:
            self.scans = scans
        if self.scan:
            self.scans = list(set([self.scan.id] + self.scans))

        # check type blacklist
        self._check_omit()

        self._scope_distance = -1

        try:
            self.data = self._sanitize_data(data)
        except Exception as e:
            log.trace(traceback.format_exc())
            raise ValidationError(f'Error sanitizing event data "{data}" for type "{self.type}": {e}')

        if not self.data:
            raise ValidationError(f'Invalid event data "{data}" for type "{self.type}"')

        self._source = None
        self._source_id = None
        self.source = source
        if (not self.source) and (not self._dummy):
            raise ValidationError(f"Must specify event source")

        # internal events are not ingested by output modules
        if not self._dummy:
            # removed this second part because it was making certain sslcert events internal
            if _internal:  # or source._internal:
                self.internal = True

        # an event indicating whether the event has undergone DNS resolution
        self._resolved = asyncio.Event()

        # inherit web spider distance from parent
        self.web_spider_distance = getattr(self.source, "web_spider_distance", 0)

    @property
    def data(self):
        return self._data

    @property
    def resolved_hosts(self):
        if is_ip(self.host):
            return {
                self.host,
            }
        return self._resolved_hosts

    @data.setter
    def data(self, data):
        self._hash = None
        self._id = None
        self.__host = None
        self._port = None
        self._data = data

    @property
    def internal(self):
        return self._internal

    @internal.setter
    def internal(self, value):
        """
        Marks the event as internal, excluding it from output but allowing normal exchange between scan modules.

        Internal events are typically speculative and may not be interesting by themselves but can lead to
        the discovery of interesting events. This method sets the `_internal` attribute to True and adds the
        "internal" tag.

        Examples of internal events include `OPEN_TCP_PORT`s from the `speculate` module,
        `IP_ADDRESS`es from the `ipneighbor` module, or out-of-scope `DNS_NAME`s that originate
        from DNS resolutions.

        The purpose of internal events is to enable speculative/explorative discovery without cluttering
        the console with irrelevant or uninteresting events.
        """
        if not value in (True, False):
            raise ValueError(f'"internal" must be boolean, not {type(value)}')
        if value == True:
            self.add_tag("internal")
        else:
            self.remove_tag("internal")
        self._internal = value

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
        if getattr(self, "parsed", None):
            if self.parsed.port is not None:
                return self.parsed.port
            elif self.parsed.scheme == "https":
                return 443
            elif self.parsed.scheme == "http":
                return 80
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
    def tags(self):
        return self._tags

    @tags.setter
    def tags(self, tags):
        if isinstance(tags, str):
            tags = (tags,)
        self._tags = set(tagify(s) for s in tags)

    def add_tag(self, tag):
        self._tags.add(tagify(tag))

    def remove_tag(self, tag):
        with suppress(KeyError):
            self._tags.remove(tagify(tag))

    @property
    def always_emit(self):
        """
        If this returns True, the event will always be distributed to output modules regardless of scope distance
        """
        always_emit_tags = any(t in self.tags for t in self._always_emit_tags)
        no_host_information = not bool(self.host)
        return self._always_emit or always_emit_tags or no_host_information

    @property
    def quick_emit(self):
        no_host_information = not bool(self.host)
        return self._quick_emit or no_host_information

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
        """
        Setter for the scope_distance attribute, ensuring it only decreases.

        The scope_distance attribute is designed to never increase; it can only be set to smaller values than
        the current one. If a larger value is provided, it is ignored. The setter also updates the event's
        tags to reflect the new scope distance.

        Parameters:
            scope_distance (int): The new scope distance to set, must be a non-negative integer.

        Note:
            The method will automatically update the relevant 'distance-' tags associated with the event.
        """
        if scope_distance >= 0:
            new_scope_distance = None
            # ensure scope distance does not increase (only allow setting to smaller values)
            if self.scope_distance == -1:
                new_scope_distance = scope_distance
            else:
                new_scope_distance = min(self.scope_distance, scope_distance)
            if self._scope_distance != new_scope_distance:
                # remove old scope distance tags
                for t in list(self.tags):
                    if t.startswith("distance-"):
                        self.remove_tag(t)
                if scope_distance == 0:
                    self.add_tag("in-scope")
                    self.remove_tag("affiliate")
                else:
                    self.remove_tag("in-scope")
                    self.add_tag(f"distance-{new_scope_distance}")
                self._scope_distance = new_scope_distance
            # apply recursively to parent events
            source_scope_distance = getattr(self.source, "scope_distance", -1)
            if source_scope_distance >= 0 and self != self.source:
                self.source.scope_distance = scope_distance + 1

    @property
    def source(self):
        return self._source

    @source.setter
    def source(self, source):
        """
        Setter for the source attribute, ensuring it's a valid event and updating scope distance.

        Sets the source of the event and automatically adjusts the scope distance based on the source event's
        scope distance. The scope distance is incremented by 1 if the host of the source event is different
        from the current event's host.

        Parameters:
            source (BaseEvent): The new source event to set. Must be a valid event object.

        Note:
            If an invalid source is provided and the event is not a dummy, a warning will be logged.
        """
        if is_event(source):
            self._source = source
            hosts_are_same = self.host and (self.host == source.host)
            if source.scope_distance >= 0:
                new_scope_distance = int(source.scope_distance)
                # only increment the scope distance if the host changes
                if self._scope_distance_increment_same_host or not hosts_are_same:
                    new_scope_distance += 1
                self.scope_distance = new_scope_distance
            # inherit certain tags
            if hosts_are_same:
                for t in source.tags:
                    if t == "affiliate":
                        self.add_tag("affiliate")
                    elif t.startswith("mutation-"):
                        self.add_tag(t)
        elif not self._dummy:
            log.warning(f"Tried to set invalid source on {self}: (got: {source})")

    @property
    def source_id(self):
        source_id = getattr(self.get_source(), "id", None)
        if source_id is not None:
            return source_id
        return self._source_id

    def get_source(self):
        """
        Takes into account events with the _omit flag
        """
        if getattr(self.source, "_omit", False):
            return self.source.get_source()
        return self.source

    def get_sources(self, omit=False):
        sources = []
        e = self
        while 1:
            if omit:
                source = e.get_source()
            else:
                source = e.source
            if e == source:
                break
            sources.append(source)
            e = source
        return sources

    def _host(self):
        return ""

    def _sanitize_data(self, data):
        """
        Validates and sanitizes the event's data during instantiation.

        By default, uses the '_data_load' method to pre-process the data and then applies the '_data_validator'
        to validate and create a sanitized dictionary. Raises a ValidationError if any of the validations fail.
        Subclasses can override this method to provide custom validation logic.

        Returns:
            Any: The sanitized data.

        Raises:
            ValidationError: If the data fails to validate.
        """
        data = self._data_load(data)
        if self._data_validator is not None:
            if not isinstance(data, dict):
                raise ValidationError(f"data is not of type dict: {data}")
            data = self._data_validator(**data).model_dump(exclude_none=True)
        return self.sanitize_data(data)

    def sanitize_data(self, data):
        return data

    @property
    def data_human(self):
        """
        Human representation of event.data
        """
        return self._data_human()

    def _data_human(self):
        if isinstance(self.data, (dict, list)):
            with suppress(Exception):
                return json.dumps(self.data, sort_keys=True)
        return smart_decode(self.data)

    def _data_load(self, data):
        """
        How to load the event data (JSON-decode it, etc.)
        """
        return data

    @property
    def data_id(self):
        """
        Representation of the event.data used to calculate the event's ID
        """
        return self._data_id()

    def _data_id(self):
        return self.data

    @property
    def pretty_string(self):
        """
        A human-friendly representation of the event's data. Used for graph representation.

        If the event's data is a dictionary, the function will try to return a JSON-formatted string.
        Otherwise, it will use smart_decode to convert the data into a string representation.

        Override if necessary.

        Returns:
            str: The graphical representation of the event's data.
        """
        return self._pretty_string()

    def _pretty_string(self):
        return self._data_human()

    @property
    def data_graph(self):
        """
        Representation of event.data for neo4j graph nodes
        """
        return self.pretty_string

    @property
    def data_json(self):
        """
        JSON representation of event.data
        """
        return self.data

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

    def json(self, mode="json", siem_friendly=False):
        """
        Serializes the event object to a JSON-compatible dictionary.

        By default, it includes attributes such as 'type', 'id', 'data', 'scope_distance', and others that are present.
        Additional specific attributes can be serialized based on the mode specified.

        Parameters:
            mode (str): Specifies the data serialization mode. Default is "json". Other options include "graph", "human", and "id".
            siem_friendly (bool): Whether to format the JSON in a way that's friendly to SIEM ingestion by Elastic, Splunk, etc. This ensures the value of "data" is always the same type (a dictionary).

        Returns:
            dict: JSON-serializable dictionary representation of the event object.
        """
        j = dict()
        for i in ("type", "id"):
            v = getattr(self, i, "")
            if v:
                j.update({i: v})
        data_attr = getattr(self, f"data_{mode}", None)
        if data_attr is not None:
            data = data_attr
        else:
            data = smart_decode(self.data)
        if siem_friendly:
            j["data"] = {self.type: data}
        else:
            j["data"] = data
        web_spider_distance = getattr(self, "web_spider_distance", None)
        if web_spider_distance is not None:
            j["web_spider_distance"] = web_spider_distance
        j["scope_distance"] = self.scope_distance
        if self.scan:
            j["scan"] = self.scan.id
        j["timestamp"] = self.timestamp.timestamp()
        if self.host:
            j["resolved_hosts"] = [str(h) for h in self.resolved_hosts]
        source_id = self.source_id
        if source_id:
            j["source"] = source_id
        if self.tags:
            j.update({"tags": list(self.tags)})
        if self.module:
            j.update({"module": str(self.module)})
        if self.module_sequence:
            j.update({"module_sequence": str(self.module_sequence)})

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

    @staticmethod
    def from_json(j):
        """
        Convenience shortcut to create an Event object from a JSON-compatible dictionary.

        Calls the `event_from_json()` function to deserialize the event.

        Parameters:
            j (dict): The JSON-compatible dictionary containing event data.

        Returns:
            Event: The deserialized Event object.
        """
        return event_from_json(j)

    @property
    def module_sequence(self):
        """
        Get a human-friendly string that represents the sequence of modules responsible for generating this event.

        Includes the names of omitted source events to provide a complete view of the module sequence leading to this event.

        Returns:
            str: The module sequence in human-friendly format.
        """
        module_name = getattr(self.module, "name", "")
        if getattr(self.source, "_omit", False):
            module_name = f"{self.source.module_sequence}->{module_name}"
        return module_name

    @property
    def module_priority(self):
        if self._module_priority is None:
            module = getattr(self, "module", None)
            self._module_priority = int(max(1, min(5, getattr(module, "priority", 3))))
        return self._module_priority

    @module_priority.setter
    def module_priority(self, priority):
        self._module_priority = int(max(1, min(5, priority)))

    @property
    def priority(self):
        if self._priority is None:
            timestamp = self.timestamp.timestamp()
            if self.source.timestamp == self.timestamp:
                self._priority = (timestamp,)
            else:
                self._priority = getattr(self.source, "priority", ()) + (timestamp,)

        return self._priority

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, val):
        self._type = val
        self._hash = None
        self._id = None
        self._check_omit()

    def _check_omit(self):
        if self.scan is not None:
            omit_event_types = self.scan.config.get("omit_event_types", [])
            if omit_event_types and self.type in omit_event_types:
                self._omit = True

    def __iter__(self):
        """
        For dict(event)
        """
        yield from self.json().items()

    def __lt__(self, other):
        """
        For queue sorting
        """
        return self.priority < getattr(other, "priority", (0,))

    def __gt__(self, other):
        """
        For queue sorting
        """
        return self.priority > getattr(other, "priority", (0,))

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
        max_event_len = 80
        d = str(self.data)
        return f'{self.type}("{d[:max_event_len]}{("..." if len(d) > max_event_len else "")}", module={self.module}, tags={self.tags})'

    def __repr__(self):
        return str(self)


class FINISHED(BaseEvent):
    """
    Special signal event to indicate end of scan
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._priority = (999999999999999999999,)


class DefaultEvent(BaseEvent):
    def sanitize_data(self, data):
        return data


class DictEvent(BaseEvent):
    def sanitize_data(self, data):
        url = data.get("url", "")
        if url:
            self.parsed = validators.validate_url_parsed(url)
        return data

    def _data_load(self, data):
        if isinstance(data, str):
            return json.loads(data)
        return data


class DictHostEvent(DictEvent):
    def _host(self):
        if isinstance(self.data, dict) and "host" in self.data:
            return make_ip_type(self.data["host"])
        else:
            parsed = getattr(self, "parsed")
            if parsed is not None:
                return make_ip_type(parsed.hostname)


class ASN(DictEvent):
    _always_emit = True
    _quick_emit = True


class CODE_REPOSITORY(DictHostEvent):
    _always_emit = True

    class _data_validator(BaseModel):
        url: str
        _validate_url = field_validator("url")(validators.validate_url)

    def _pretty_string(self):
        return self.data["url"]


class IP_ADDRESS(BaseEvent):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        ip = ipaddress.ip_address(self.data)
        self.add_tag(f"ipv{ip.version}")
        if ip.is_private:
            self.add_tag("private")
        self.dns_resolve_distance = getattr(self.source, "dns_resolve_distance", 0)

    def sanitize_data(self, data):
        return validators.validate_host(data)

    def _host(self):
        return ipaddress.ip_address(self.data)


class DnsEvent(BaseEvent):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # prevent runaway DNS entries
        self.dns_resolve_distance = 0
        source = getattr(self, "source", None)
        module = getattr(self, "module", None)
        module_type = getattr(module, "_type", "")
        source_module = getattr(source, "module", None)
        source_module_type = getattr(source_module, "_type", "")
        if module_type == "DNS":
            self.dns_resolve_distance = getattr(source, "dns_resolve_distance", 0)
            if source_module_type == "DNS":
                self.dns_resolve_distance += 1
        # self.add_tag(f"resolve-distance-{self.dns_resolve_distance}")


class IP_RANGE(DnsEvent):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        net = ipaddress.ip_network(self.data, strict=False)
        self.add_tag(f"ipv{net.version}")

    def sanitize_data(self, data):
        return str(ipaddress.ip_network(str(data), strict=False))

    def _host(self):
        return ipaddress.ip_network(self.data)


class DNS_NAME(DnsEvent):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if is_subdomain(self.data):
            self.add_tag("subdomain")
        elif is_domain(self.data):
            self.add_tag("domain")

    def sanitize_data(self, data):
        return validators.validate_host(data)

    def _host(self):
        return self.data

    def _words(self):
        stem = self.host_stem
        if not is_ptr(stem):
            split_stem = stem.split(".")
            if split_stem:
                leftmost_segment = split_stem[0]
                if leftmost_segment == "_wildcard":
                    stem = ".".join(split_stem[1:])
            if stem:
                return extract_words(stem)
        return set()


class OPEN_TCP_PORT(BaseEvent):
    def sanitize_data(self, data):
        return validators.validate_open_port(data)

    def _host(self):
        host, self._port = split_host_port(self.data)
        return host

    def _words(self):
        if not is_ip(self.host) and not is_ptr(self.host):
            return extract_words(self.host_stem)
        return set()


class URL_UNVERIFIED(BaseEvent):
    _status_code_regex = re.compile(r"^status-(\d{1,3})$")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # increment the web spider distance
        if self.type == "URL_UNVERIFIED" and getattr(self.module, "name", "") != "TARGET":
            self.web_spider_distance += 1
        self.num_redirects = getattr(self.source, "num_redirects", 0)

    def sanitize_data(self, data):
        self.parsed = validators.validate_url_parsed(data)

        # tag as dir or endpoint
        if str(self.parsed.path).endswith("/"):
            self.add_tag("dir")
        else:
            self.add_tag("endpoint")

        parsed_path_lower = str(self.parsed.path).lower()

        scan = getattr(self, "scan", None)
        url_extension_blacklist = getattr(scan, "url_extension_blacklist", [])
        url_extension_httpx_only = getattr(scan, "url_extension_httpx_only", [])

        extension = get_file_extension(parsed_path_lower)
        if extension:
            self.add_tag(f"extension-{extension}")
            if extension in url_extension_blacklist:
                self.add_tag("blacklisted")
            if extension in url_extension_httpx_only:
                self.add_tag("httpx-only")
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

    def _data_id(self):
        # consider spider-danger tag when deduping
        data = super()._data_id()
        if "spider-danger" in self.tags:
            data = "spider-danger" + data
        return data

    @property
    def http_status(self):
        for t in self.tags:
            match = self._status_code_regex.match(t)
            if match:
                return int(match.groups()[0])
        return 0


class URL(URL_UNVERIFIED):
    def sanitize_data(self, data):
        if not self._dummy and not any(t.startswith("status-") for t in self.tags):
            raise ValidationError(
                'Must specify HTTP status tag for URL event, e.g. "status-200". Use URL_UNVERIFIED if the URL is unvisited.'
            )
        return super().sanitize_data(data)

    @property
    def resolved_hosts(self):
        return [".".join(i.split("-")[1:]) for i in self.tags if i.startswith("ip-")]

    @property
    def pretty_string(self):
        return self.data


class STORAGE_BUCKET(DictEvent, URL_UNVERIFIED):
    _always_emit = True

    class _data_validator(BaseModel):
        name: str
        url: str
        _validate_url = field_validator("url")(validators.validate_url)

    def sanitize_data(self, data):
        data = super().sanitize_data(data)
        data["name"] = data["name"].lower()
        return data

    def _words(self):
        return self.data["name"]


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
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # count number of consecutive redirects
        self.num_redirects = getattr(self.source, "num_redirects", 0)
        if str(self.http_status).startswith("3"):
            self.num_redirects += 1

    def sanitize_data(self, data):
        url = data.get("url", "")
        self.parsed = validators.validate_url_parsed(url)
        data["url"] = self.parsed.geturl()

        header_dict = {}
        for i in data.get("raw_header", "").splitlines():
            if len(i) > 0 and ":" in i:
                k, v = i.split(":", 1)
                k = k.strip().lower()
                v = v.lstrip()
                header_dict[k] = v
        data["header-dict"] = header_dict
        # move URL to the front of the dictionary for visibility
        data = dict(data)
        new_data = {"url": data.pop("url")}
        new_data.update(data)

        return new_data

    def _words(self):
        return set()

    def _pretty_string(self):
        return f'{self.data["hash"]["header_mmh3"]}:{self.data["hash"]["body_mmh3"]}'

    @property
    def http_status(self):
        try:
            return int(self.data.get("status_code", 0))
        except (ValueError, TypeError):
            return 0

    @property
    def http_title(self):
        http_title = self.data.get("title", "")
        try:
            return recursive_decode(http_title)
        except Exception:
            return http_title

    @property
    def redirect_location(self):
        location = self.data.get("location", "")
        # if it's a redirect
        if location:
            # get the url scheme
            scheme = is_uri(location, return_scheme=True)
            # if there's no scheme (i.e. it's a relative redirect)
            if not scheme:
                # then join the location with the current url
                location = urljoin(self.parsed.geturl(), location)
        return location


class VULNERABILITY(DictHostEvent):
    _always_emit = True
    _quick_emit = True
    severity_colors = {
        "CRITICAL": "🟪",
        "HIGH": "🟥",
        "MEDIUM": "🟧",
        "LOW": "🟨",
        "UNKNOWN": "⬜",
    }

    def sanitize_data(self, data):
        self.add_tag(data["severity"].lower())
        return data

    class _data_validator(BaseModel):
        host: str
        severity: str
        description: str
        url: Optional[str] = None
        _validate_url = field_validator("url")(validators.validate_url)
        _validate_host = field_validator("host")(validators.validate_host)
        _validate_severity = field_validator("severity")(validators.validate_severity)

    def _pretty_string(self):
        return f'[{self.data["severity"]}] {self.data["description"]}'


class FINDING(DictHostEvent):
    _always_emit = True
    _quick_emit = True

    class _data_validator(BaseModel):
        host: str
        description: str
        url: Optional[str] = None
        _validate_url = field_validator("url")(validators.validate_url)
        _validate_host = field_validator("host")(validators.validate_host)

    def _pretty_string(self):
        return self.data["description"]


class TECHNOLOGY(DictHostEvent):
    class _data_validator(BaseModel):
        host: str
        technology: str
        url: Optional[str] = None
        _validate_url = field_validator("url")(validators.validate_url)
        _validate_host = field_validator("host")(validators.validate_host)

    def _data_id(self):
        # dedupe by host+port+tech
        tech = self.data.get("technology", "")
        return f"{self.host}:{self.port}:{tech}"

    def _pretty_string(self):
        return self.data["technology"]


class VHOST(DictHostEvent):
    class _data_validator(BaseModel):
        host: str
        vhost: str
        url: Optional[str] = None
        _validate_url = field_validator("url")(validators.validate_url)
        _validate_host = field_validator("host")(validators.validate_host)

    def _pretty_string(self):
        return self.data["vhost"]


class PROTOCOL(DictHostEvent):
    class _data_validator(BaseModel):
        host: str
        protocol: str
        port: Optional[int] = None
        banner: Optional[str] = None
        _validate_host = field_validator("host")(validators.validate_host)
        _validate_port = field_validator("port")(validators.validate_port)

    def sanitize_data(self, data):
        new_data = dict(data)
        new_data["protocol"] = data.get("protocol", "").upper()
        return new_data

    @property
    def port(self):
        return self.data.get("port", None)

    def _pretty_string(self):
        return self.data["protocol"]


class GEOLOCATION(BaseEvent):
    _always_emit = True
    _quick_emit = True


class PASSWORD(BaseEvent):
    _always_emit = True
    _quick_emit = True


class HASHED_PASSWORD(BaseEvent):
    _always_emit = True
    _quick_emit = True


class USERNAME(BaseEvent):
    _always_emit = True
    _quick_emit = True


class SOCIAL(DictHostEvent):
    _always_emit = True
    _quick_emit = True
    _scope_distance_increment_same_host = True


class WEBSCREENSHOT(DictHostEvent):
    _always_emit = True
    _quick_emit = True


class AZURE_TENANT(DictEvent):
    _always_emit = True
    _quick_emit = True


class WAF(DictHostEvent):
    _always_emit = True
    _quick_emit = True

    class _data_validator(BaseModel):
        url: str
        host: str
        waf: str
        info: Optional[str] = None
        _validate_url = field_validator("url")(validators.validate_url)
        _validate_host = field_validator("host")(validators.validate_host)

    def _pretty_string(self):
        return self.data["waf"]


def make_event(
    data,
    event_type=None,
    source=None,
    module=None,
    scan=None,
    scans=None,
    tags=None,
    confidence=5,
    dummy=False,
    internal=None,
):
    """
    Creates and returns a new event object or modifies an existing one.

    This function serves as a factory for creating new event objects, either by generating a new `Event`
    object or by updating an existing event with additional metadata. If `data` is already an event,
    it updates the event based on the additional parameters provided.

    Parameters:
        data (Union[str, dict, BaseEvent]): The primary data for the event or an existing event object.
        event_type (str, optional): Type of the event, e.g., 'IP_ADDRESS'. Auto-detected if not provided.
        source (BaseEvent, optional): Source event leading to this event's discovery.
        module (str, optional): Module that discovered the event.
        scan (Scan, optional): BBOT Scan object associated with the event.
        scans (List[Scan], optional): Multiple BBOT Scan objects, primarily used for unserialization.
        tags (Union[str, List[str]], optional): Descriptive tags for the event, as a list or a single string.
        confidence (int, optional): Confidence level for the event, on a scale of 1-10. Defaults to 5.
        dummy (bool, optional): Disables data validations if set to True. Defaults to False.
        internal (Any, optional): Makes the event internal if set to True. Defaults to None.

    Returns:
        BaseEvent: A new or updated event object.

    Raises:
        ValidationError: Raised when there's an error in event data or type sanitization.

    Examples:
        If inside a module, e.g. from within its `handle_event()`:
        >>> self.make_event("1.2.3.4", source=event)
        IP_ADDRESS("1.2.3.4", module=nmap, tags={'ipv4', 'distance-1'})

        If you're outside a module but you have a scan object:
        >>> scan.make_event("1.2.3.4", source=scan.root_event)
        IP_ADDRESS("1.2.3.4", module=None, tags={'ipv4', 'distance-1'})

        If you're outside a scan and just messing around:
        >>> from bbot.core.event.base import make_event
        >>> make_event("1.2.3.4", dummy=True)
        IP_ADDRESS("1.2.3.4", module=None, tags={'ipv4'})

    Note:
        When working within a module's `handle_event()`, use the instance method
        `self.make_event()` instead of calling this function directly.
    """

    # allow tags to be either a string or an array
    if not tags:
        tags = []
    elif isinstance(tags, str):
        tags = [tags]
    tags = set(tags)

    if is_event(data):
        data = copy(data)
        if scan is not None and not data.scan:
            data.scan = scan
        if scans is not None and not data.scans:
            data.scans = scans
        if module is not None:
            data.module = module
        if source is not None:
            data.source = source
        if internal == True:
            data.internal = True
        if tags:
            data.tags = tags.union(data.tags)
        event_type = data.type
        return data
    else:
        if event_type is None:
            event_type, data = get_event_type(data)
            if not dummy:
                log.debug(f'Autodetected event type "{event_type}" based on data: "{data}"')

        event_type = str(event_type).strip().upper()

        # Catch these common whoopsies
        if event_type in ("DNS_NAME", "IP_ADDRESS"):
            # DNS_NAME <--> EMAIL_ADDRESS confusion
            if validators.soft_validate(data, "email"):
                event_type = "EMAIL_ADDRESS"
            else:
                # DNS_NAME <--> IP_ADDRESS confusion
                try:
                    data = validators.validate_host(data)
                except Exception as e:
                    log.trace(traceback.format_exc())
                    raise ValidationError(f'Error sanitizing event data "{data}" for type "{event_type}": {e}')
                data_is_ip = is_ip(data)
                if event_type == "DNS_NAME" and data_is_ip:
                    event_type = "IP_ADDRESS"
                elif event_type == "IP_ADDRESS" and not data_is_ip:
                    event_type = "DNS_NAME"
        # USERNAME <--> EMAIL_ADDRESS confusion
        if event_type == "USERNAME" and validators.soft_validate(data, "email"):
            event_type = "EMAIL_ADDRESS"
            tags.add("affiliate")

        event_class = globals().get(event_type, DefaultEvent)

        return event_class(
            data,
            event_type=event_type,
            source=source,
            module=module,
            scan=scan,
            scans=scans,
            tags=tags,
            confidence=confidence,
            _dummy=dummy,
            _internal=internal,
        )


def event_from_json(j, siem_friendly=False):
    """
    Creates an event object from a JSON dictionary.

    This function deserializes a JSON dictionary to create a new event object, using the `make_event` function
    for the actual object creation. It sets additional attributes such as the timestamp and scope distance
    based on the input JSON.

    Parameters:
        j (Dict): JSON dictionary containing the event attributes.
                  Must include keys "data" and "type".

    Returns:
        BaseEvent: A new event object initialized with attributes from the JSON dictionary.

    Raises:
        ValidationError: Raised when the JSON dictionary is missing required fields.

    Note:
        The function assumes that the input JSON dictionary is valid and may raise exceptions
        if required keys are missing. Make sure to validate the JSON input beforehand.
    """
    try:
        event_type = j["type"]
        kwargs = {
            "event_type": event_type,
            "scans": j.get("scans", []),
            "tags": j.get("tags", []),
            "confidence": j.get("confidence", 5),
            "dummy": True,
        }
        if siem_friendly:
            data = j["data"][event_type]
        else:
            data = j["data"]
        kwargs["data"] = data
        event = make_event(**kwargs)

        resolved_hosts = j.get("resolved_hosts", [])
        event._resolved_hosts = set(resolved_hosts)

        event.timestamp = datetime.fromtimestamp(j["timestamp"])
        event.scope_distance = j["scope_distance"]
        source_id = j.get("source", None)
        if source_id is not None:
            event._source_id = source_id
        return event
    except KeyError as e:
        raise ValidationError(f"Event missing required field: {e}")


def is_event(e):
    return BaseEvent in e.__class__.__mro__
