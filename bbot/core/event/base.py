import io
import re
import sys
import uuid
import json
import base64
import logging
import tarfile
import datetime
import ipaddress
import traceback

from pathlib import Path
from typing import Optional
from zoneinfo import ZoneInfo
from copy import copy, deepcopy
from types import MappingProxyType
from contextlib import suppress
from radixtarget import RadixTarget
from pydantic import BaseModel, field_validator
from urllib.parse import urlparse, urljoin, parse_qs


from bbot.errors import *
from .helpers import EventSeed
from bbot.core.helpers import (
    bytes_to_human,
    extract_words,
    is_domain,
    is_subdomain,
    is_ip,
    is_ip_type,
    is_ptr,
    is_uri,
    url_depth,
    domain_stem,
    make_netloc,
    make_ip_type,
    cached_ip_address,
    recursive_decode,
    sha1,
    smart_decode,
    split_host_port,
    tagify,
    validators,
    get_file_extension,
)
from bbot.models.helpers import utc_datetime_validator
from bbot.core.helpers.web.envelopes import BaseEnvelope


log = logging.getLogger("bbot.core.event")


# Shared empty defaults for lazy-init slots. Returned from property accessors
# when the underlying slot is None — saves ~560 bytes per event compared to
# allocating real empty containers (set/dict) at __init__ time. Mutating
# helpers (add_tag, etc.) replace the slot with a real container before
# mutating, so callers never see the singletons in a mutable position.
# `_resolved_hosts` has no in-place mutation API — see the resolved_hosts
# property setter for the assign-once-then-frozen contract.
_EMPTY_FROZENSET: "frozenset[str]" = frozenset()
_EMPTY_DICT = MappingProxyType({})


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
        id (str): An identifier for the event (event type + sha1 hash of data). NOT universally unique.
        uuid (UUID): A universally unique identifier for the event.
        data (str or dict): The main data for the event, e.g., a URL or IP address.
        data_graph (str): Representation of `self.data` for graph nodes (e.g. Neo4j).
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
        parent (BaseEvent): The parent event that led to the discovery of this event.
        parent_id (str): The `id` attribute of the parent event.
        parent_uuid (str): The `uuid` attribute of the parent event.
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
            "parent": "OPEN_TCP_PORT:cf7e6a937b161217eaed99f0c566eae045d094c7",
            "tags": ["in-scope", "distance-0", "dir", "status-301"],
            "http_title": "301 Moved Permanently",
            "module": "http",
            "module_sequence": "http"
        }
        ```
    """

    # Always emit this event type even if it's not in scope
    _always_emit = False
    # Always emit events with these tags even if they're not in scope

    _always_emit_tags = ["affiliate", "seed"]
    # Bypass scope checking and dns resolution, distribute immediately to modules
    # This is useful for "end-of-line" events like FINDING
    _quick_emit = False
    # Data validation, if data is a dictionary
    _data_validator = None
    # Whether to increment scope distance if the child and parent hosts are the same
    # Normally we don't want this, since scope distance only increases if the host changes
    # But for some events like SOCIAL media profiles, this is required to prevent spidering all of facebook.com
    _scope_distance_increment_same_host = False
    # Don't allow duplicates to occur within a parent chain
    # In other words, don't emit the event if the same one already exists in its discovery context
    _suppress_chain_dupes = False
    # Shared compiled regex for discovery context formatting (class-level to avoid per-instance overhead)
    _discovery_context_regex = re.compile(r"\{(?:event|module)[^}]*\}")
    # Stats class for the status line — override in subclasses for custom formatting
    _stats_class = None

    # using __slots__ dramatically reduces memory usage in large scans
    __slots__ = [
        # Core identification attributes
        "_uuid",
        "_id",
        "_hash",
        "_data",
        "_data_hash",
        # Host-related attributes
        "__host",
        "_host_original",
        "_port",
        # Parent-related attributes
        "_parent",
        "_parent_id",
        "_parent_uuid",
        # Event metadata
        "_type",
        "_tags",
        "_omit",
        "__words",
        "_priority",
        "_scope_distance",
        "_module_priority",
        "_graph_important",
        "_resolved_hosts",
        "_discovery_context",
        "_stats_recorded",
        "_internal",
        "_dummy",
        "_module",
        # DNS-related attributes — backing slots; public access via the
        # ``dns_children`` / ``raw_dns_records`` properties so a None
        # underlying slot transparently reads as an empty dict (lazy-init
        # saves ~128 bytes per event).
        "_dns_children",
        "_raw_dns_records",
        "dns_resolve_distance",
        # Host metadata (cloud providers, ASN, whois, etc.)
        "_host_metadata",
        "_cloudcheck_done",
        # Memory management
        "_module_consumers",
        # Public attributes
        "module",
        "scan",
        "timestamp",
    ]

    def __init__(
        self,
        data,
        event_type,
        parent=None,
        context=None,
        module=None,
        scan=None,
        tags=None,
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
            parent (BaseEvent, optional): Parent event that led to this event's discovery. Defaults to None.
            module (str, optional): Module that discovered the event. Defaults to None.
            scan (Scan, optional): BBOT Scan object. Required unless _dummy is True. Defaults to None.
            tags (list of str, optional): Descriptive tags for the event. Defaults to None.
            timestamp (datetime, optional): Time of event discovery. Defaults to current UTC time.
            _dummy (bool, optional): If True, disables certain data validations. Defaults to False.
            _internal (Any, optional): If specified, makes the event internal. Defaults to None.

        Raises:
            ValidationError: If either `scan` or `parent` are not specified and `_dummy` is False.
        """
        self._uuid = uuid.uuid4()
        self._id = None
        self._hash = None
        self._data = None
        self.__host = None
        # Lazy-init: replaced with a real set/dict on first mutation.
        # Reading via the property returns a shared empty frozenset/dict
        # so callers never see None.
        self._tags = None
        self._port = None
        self._omit = False
        self.__words = None
        self._parent = None
        self._priority = None
        self._parent_id = None
        self._parent_uuid = None
        self._host_original = None
        self._scope_distance = None
        self._module_priority = None
        self._graph_important = False
        self._resolved_hosts = None
        self._dns_children = None
        self._raw_dns_records = None
        self._discovery_context = ""
        self._module_consumers = 0

        # for creating one-off events without enforcing parent requirement
        self._dummy = _dummy
        self.module = module
        self._type = event_type

        # keep track of whether this event has been recorded by the scan
        self._stats_recorded = False

        if timestamp is not None:
            self.timestamp = timestamp
        else:
            try:
                self.timestamp = datetime.datetime.now(datetime.UTC)
            except AttributeError:
                self.timestamp = datetime.datetime.utcnow()

        self._internal = False

        # self.scan holds the instantiated scan object (for helpers, etc.)
        self.scan = scan
        if (not self.scan) and (not self._dummy):
            raise ValidationError("Must specify scan")

        try:
            self.data = self._sanitize_data(data)
        except Exception as e:
            log.trace(traceback.format_exc())
            data_preview = str(data)[:200] + "..." if len(str(data)) > 200 else str(data)
            raise ValidationError(f'Error sanitizing event data "{data_preview}" for type "{self.type}": {e}')

        if not self.data:
            raise ValidationError(f'Invalid event data "{data}" for type "{self.type}"')

        self.parent = parent
        if (not self.parent) and (not self._dummy):
            raise ValidationError("Must specify event parent")

        if tags is not None:
            for tag in tags:
                self.add_tag(tag)

        # internal events are not ingested by output modules
        if not self._dummy:
            # removed this second part because it was making certain sslcert events internal
            if _internal:  # or parent._internal:
                self.internal = True

        if not context:
            context = getattr(self.module, "default_discovery_context", "")
        if context:
            self.discovery_context = context

    @property
    def data(self):
        return self._data

    @property
    def resolved_hosts(self):
        if is_ip(self.host):
            return frozenset({self.host})
        return self._resolved_hosts if self._resolved_hosts is not None else _EMPTY_FROZENSET

    @resolved_hosts.setter
    def resolved_hosts(self, value):
        """Assign ``_resolved_hosts`` as a frozenset (or None for unset).

        Resolved hosts are naturally immutable: there is no in-place mutation
        API. Callers (typically ``dnsresolve``) build the set locally and then
        assign it once via this setter, after which the slot holds a
        ``frozenset`` that downstream consumers can read but cannot modify.
        """
        if value is None:
            self._resolved_hosts = None
        elif isinstance(value, frozenset):
            self._resolved_hosts = value
        else:
            self._resolved_hosts = frozenset(value)

    @property
    def dns_children(self):
        return self._dns_children if self._dns_children is not None else _EMPTY_DICT

    @property
    def raw_dns_records(self):
        return self._raw_dns_records if self._raw_dns_records is not None else _EMPTY_DICT

    def add_dns_child(self, rdtype, host):
        """Record a DNS child host under ``rdtype``, lazy-allocating dict + child set."""
        if self._dns_children is None:
            self._dns_children = {}
        existing = self._dns_children.get(rdtype)
        if existing is None:
            self._dns_children[rdtype] = {host}
        else:
            existing.add(host)

    def set_raw_dns_record(self, rdtype, answers):
        """Store the raw DNS answer list for ``rdtype``, lazy-allocating the dict."""
        if self._raw_dns_records is None:
            self._raw_dns_records = {}
        self._raw_dns_records[rdtype] = answers

    @data.setter
    def data(self, data):
        self._hash = None
        self._data_hash = None
        self._id = None
        self.__host = None
        self._port = None
        self._data = data

    @property
    def host_metadata(self):
        try:
            return self._host_metadata
        except AttributeError:
            self._host_metadata = {}
            return self._host_metadata

    @host_metadata.setter
    def host_metadata(self, value):
        self._host_metadata = value

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
        if value not in (True, False):
            raise ValueError(f'"internal" must be boolean, not {type(value)}')
        if value is True:
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
            self.host = self._host()
        return self.__host

    @host.setter
    def host(self, host):
        if self._host_original is None:
            self._host_original = host
        self.__host = host

    @property
    def host_original(self):
        """
        Original host data, in case it was changed due to a wildcard DNS, etc.
        """
        if self._host_original is None:
            return self.host
        return self._host_original

    @property
    def url(self):
        parsed_url = getattr(self, "parsed_url", None)
        if parsed_url is not None:
            return parsed_url.geturl()
        return ""

    @property
    def host_filterable(self):
        """
        A string version of the event that's used for regex-based blacklisting.

        For example, the user can specify "REGEX:.*.evilcorp.com" in their blacklist, and this regex
        will be applied against this property.
        """
        parsed_url = getattr(self, "parsed_url", None)
        if parsed_url is not None:
            return parsed_url.geturl()
        if self.host is not None:
            return str(self.host)
        return ""

    @property
    def port(self):
        self.host
        if self._port:
            return self._port
        if getattr(self, "parsed_url", None):
            if self.parsed_url.port is not None:
                return self.parsed_url.port
            elif self.parsed_url.scheme == "https":
                return 443
            elif self.parsed_url.scheme == "http":
                return 80

    @property
    def netloc(self):
        if self.host and is_ip_type(self.host, network=False):
            return make_netloc(self.host, self.port)
        return None

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
    def discovery_context(self):
        return self._discovery_context

    @discovery_context.setter
    def discovery_context(self, context):
        def replace(match):
            s = match.group()
            return s.format(module=self.module, event=self)

        try:
            self._discovery_context = self._discovery_context_regex.sub(replace, context)
        except Exception as e:
            log.trace(f"Error formatting discovery context for {self}: {e} (context: '{context}')")
            self._discovery_context = context

    @property
    def discovery_path(self):
        """
        This event's full discovery context, including those of all its parents
        """
        discovery_path = []
        if self.parent is not None and self.parent is not self:
            discovery_path = self.parent.discovery_path
        return discovery_path + [self.discovery_context]

    @property
    def parent_chain(self):
        """
        This event's full discovery context, including those of all its parents
        """
        parent_chain = []
        if self.parent is not None and self.parent is not self:
            parent_chain = self.parent.parent_chain
        return parent_chain + [str(self.uuid)]

    @property
    def words(self):
        if self.__words is None:
            self.__words = set(self._words())
        return self.__words

    def _words(self):
        return set()

    @property
    def tags(self):
        return self._tags if self._tags is not None else _EMPTY_FROZENSET

    @tags.setter
    def tags(self, tags):
        self._tags = set()
        if isinstance(tags, str):
            tags = (tags,)
        for tag in tags:
            self.add_tag(tag)

    def add_tag(self, tag):
        if self._tags is None:
            self._tags = set()
        self._tags.add(sys.intern(tagify(tag)))

    def add_tags(self, tags):
        for tag in set(tags):
            self.add_tag(tag)

    def remove_tag(self, tag):
        if not self._tags:
            return
        with suppress(KeyError):
            self._tags.remove(sys.intern(tagify(tag)))

    @property
    def always_emit(self):
        """
        If this returns True, the event will always be distributed to output modules regardless of scope distance
        """
        always_emit_tags = any(t in self.tags for t in self._always_emit_tags)
        no_host_information = not bool(self.host)
        return self._always_emit or always_emit_tags or no_host_information

    @property
    def id(self):
        """
        A uniquely identifiable hash of the event from the event type + a SHA1 of its data
        """
        if self._id is None:
            self._id = f"{self.type}:{self.data_hash.hex()}"
        return self._id

    @property
    def uuid(self):
        """
        A universally unique identifier for the event
        """
        return f"{self.type}:{self._uuid}"

    @property
    def data_hash(self):
        """
        A raw byte hash of the event's data
        """
        if self._data_hash is None:
            self._data_hash = sha1(self.data_id).digest()
        return self._data_hash

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
        if scope_distance < 0:
            raise ValueError(f"Invalid scope distance: {scope_distance}")
        # ensure scope distance does not increase (only allow setting to smaller values)
        if self.scope_distance is None:
            new_scope_distance = scope_distance
        else:
            new_scope_distance = min(self.scope_distance, scope_distance)
        if self._scope_distance != new_scope_distance:
            # remove old scope distance tags
            self._scope_distance = new_scope_distance
            self.refresh_scope_tags()
            # apply recursively to parent events
            parent_scope_distance = getattr(self.parent, "scope_distance", None)
            if parent_scope_distance is not None and self.parent is not self:
                self.parent.scope_distance = new_scope_distance + 1

    def refresh_scope_tags(self):
        for t in list(self.tags):
            if t.startswith("distance-"):
                self.remove_tag(t)
        if self.host:
            if self.scope_distance == 0:
                self.add_tag("in-scope")
                self.remove_tag("affiliate")
            else:
                self.remove_tag("in-scope")
                self.add_tag(f"distance-{self.scope_distance}")

    @property
    def scope_description(self):
        """
        Returns a single word describing the scope of the event.

        "in-scope" if the event is in scope, "affiliate" if it's an affiliate, otherwise "distance-{scope_distance}"
        """
        if self.scope_distance == 0:
            return "in-scope"
        elif "affiliate" in self.tags:
            return "affiliate"
        return f"distance-{self.scope_distance}"

    @property
    def parent(self):
        return self._parent

    @parent.setter
    def parent(self, parent):
        """
        Setter for the parent attribute, ensuring it's a valid event and updating scope distance.

        Sets the parent of the event and automatically adjusts the scope distance based on the parent event's
        scope distance. The scope distance is incremented by 1 if the host of the parent event is different
        from the current event's host.

        Parameters:
            parent (BaseEvent): The new parent event to set. Must be a valid event object.

        Note:
            If an invalid parent is provided and the event is not a dummy, a warning will be logged.
        """
        if is_event(parent):
            self._parent = parent
            hosts_are_same = (self.host and parent.host) and (self.host == parent.host)
            new_scope_distance = int(parent.scope_distance)
            if self.host and parent.scope_distance is not None:
                # only increment the scope distance if the host changes
                if self._scope_distance_increment_same_host or not hosts_are_same:
                    new_scope_distance += 1
            self.scope_distance = new_scope_distance
            # inherit certain tags
            # inherit seed tag from DNS_NAME_UNRESOLVED -> DNS_NAME only
            if "seed" in parent.tags and parent.type == "DNS_NAME_UNRESOLVED" and self.type == "DNS_NAME":
                self.add_tag("seed")
            if hosts_are_same:
                # inherit web spider distance from parent
                self.web_spider_distance = getattr(parent, "web_spider_distance", 0)
                event_has_url = getattr(self, "parsed_url", None) is not None
                for t in parent.tags:
                    if t in ("affiliate", "from-wayback", "from-lightfuzz"):
                        self.add_tag(t)
                    elif t.startswith("mutation-"):
                        self.add_tag(t)
                    # only add these tags if the event has a URL
                    if event_has_url:
                        if t in ("spider-danger", "spider-max"):
                            self.add_tag(t)
        elif not self._dummy:
            log.warning(f"Tried to set invalid parent on {self}: (got: {repr(parent)} ({type(parent)}))")

    @property
    def children(self):
        return []

    @property
    def parent_id(self):
        parent_id = getattr(self.get_parent(), "id", None)
        if parent_id is not None:
            return parent_id
        return self._parent_id

    @property
    def parent_uuid(self):
        parent_uuid = getattr(self.get_parent(), "uuid", None)
        if parent_uuid is not None:
            return parent_uuid
        return self._parent_uuid

    @property
    def archive_url(self):
        """Traverse the parent chain to find the nearest archive_url.

        The 'from-wayback' tag signals that this event descends from archived content.
        The actual archive URL is stored only in the data dict of the originating
        wayback HTTP_RESPONSE; this property walks upward to find it.
        """
        if "from-wayback" not in self.tags:
            return None
        event = self
        while event is not None:
            if isinstance(event.data, dict) and "archive_url" in event.data:
                return event.data["archive_url"]
            parent = getattr(event, "parent", None)
            if parent is None or parent is event:
                break
            event = parent
        return None

    @property
    def validators(self):
        """
        Depending on whether the scan attribute is accessible, return either a config-aware or non-config-aware validator

        This exists to prevent a chicken-and-egg scenario during the creation of certain events such as URLs,
        whose sanitization behavior is different depending on the config.

        However, thanks to this property, validation can still work in the absence of a config.
        """
        if self.scan is not None:
            return self.scan.helpers.config_aware_validators
        return validators

    def get_parent(self):
        """
        Takes into account events with the _omit flag
        """
        if getattr(self.parent, "_omit", False):
            return self.parent.get_parent()
        return self.parent

    def get_parents(self, omit=False, include_self=False):
        parents = []
        e = self
        if include_self:
            parents.append(self)
        while 1:
            if omit:
                parent = e.get_parent()
            else:
                parent = e.parent
            if parent is None:
                break
            if e == parent:
                break
            parents.append(parent)
            e = parent
        return parents

    def _minimize(self):
        """
        Called when a module is done processing this event.

        Decrements the consumer count. When no modules are left waiting to
        process this event, heavy payload data is stripped to free memory.
        """
        self._module_consumers = max(0, self._module_consumers - 1)
        if self._module_consumers <= 0:
            # release container slots; lazy-init pattern means None == empty
            self._dns_children = None
            self._raw_dns_records = None
            self._resolved_hosts = None

    def clone(self):
        # Create a shallow copy of the event first
        cloned_event = copy(self)
        # Re-assign a new UUID
        cloned_event._uuid = uuid.uuid4()
        return cloned_event

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
        Membership checks for Events.

        Supports:
            - some_event in other_event   (event vs event)
            - "host:port" in other_event  (string coerced to an event)
        """
        # Fast path: already an Event
        if is_event(other):
            other_event = other
        else:
            try:
                other_event = make_event(other, dummy=True)
            except ValidationError:
                return False

        # if hashes match
        if other_event == self:
            return True
        # if hosts match (including subnet / domain containment)
        if self.host and other_event.host:
            if self.host == other_event.host:
                return True
            # hostnames and IPs
            radixtarget = RadixTarget()
            radixtarget.insert(str(self.host))
            return bool(radixtarget.search(str(other_event.host)))
        return False

    def json(self, mode="json"):
        """
        Serializes the event object to a JSON-compatible dictionary.

        By default, it includes attributes such as 'type', 'id', 'data', 'scope_distance', and others that are present.
        Additional specific attributes can be serialized based on the mode specified.

        Parameters:
            mode (str): Specifies the data serialization mode. Default is "json". Other options include "graph", "human", and "id".

        Returns:
            dict: JSON-serializable dictionary representation of the event object.
        """
        j = {}
        # type, ID, scope description
        for i in ("type", "id", "uuid", "scope_description", "netloc"):
            v = getattr(self, i, "")
            if v:
                j.update({i: str(v)})
        # event data
        data_attr = getattr(self, f"data_{mode}", None)
        if data_attr is not None:
            data = data_attr
        else:
            data = smart_decode(self.data)
        if isinstance(data, str):
            j["data"] = data
        elif isinstance(data, dict):
            j["data_json"] = data
        else:
            raise ValueError(f"Invalid data type: {type(data)}")
        # host, dns children
        if self.host:
            j["host"] = str(self.host)
            j["resolved_hosts"] = sorted(str(h) for h in self.resolved_hosts)
            j["dns_children"] = {k: list(v) for k, v in self.dns_children.items()}
        if isinstance(self.port, int):
            j["port"] = self.port
        # web spider distance
        web_spider_distance = getattr(self, "web_spider_distance", None)
        if web_spider_distance is not None:
            j["web_spider_distance"] = web_spider_distance
        # scope distance
        j["scope_distance"] = self.scope_distance
        # scan
        if self.scan:
            j["scan"] = self.scan.id
        # timestamp
        j["timestamp"] = utc_datetime_validator(self.timestamp).timestamp()
        # parent event
        parent_id = self.parent_id
        if parent_id:
            j["parent"] = parent_id
        parent_uuid = self.parent_uuid
        if parent_uuid:
            j["parent_uuid"] = parent_uuid
        # tags
        j.update({"tags": sorted(self.tags)})
        # parent module
        if self.module:
            j.update({"module": str(self.module)})
        # sequence of modules that led to discovery
        if self.module_sequence:
            j.update({"module_sequence": str(self.module_sequence)})
        # discovery context
        j["discovery_context"] = self.discovery_context
        j["discovery_path"] = self.discovery_path
        j["parent_chain"] = self.parent_chain

        # host metadata (cloud providers, ASN, etc.)
        host_metadata = getattr(self, "host_metadata", None)
        if host_metadata:
            j["host_metadata"] = host_metadata
        # parameter envelopes
        parameter_envelopes = getattr(self, "envelopes", None)
        if parameter_envelopes is not None:
            j["envelopes"] = parameter_envelopes.to_dict()

        # normalize non-primitive python objects

        for k, v in list(j.items()):
            if k == "data":
                continue
            if type(v) not in (str, int, float, bool, list, dict, type(None)):
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

        Includes the names of omitted parent events to provide a complete view of the module sequence leading to this event.

        Returns:
            str: The module sequence in human-friendly format.
        """
        module_name = getattr(self.module, "name", "")
        if getattr(self.parent, "_omit", False):
            module_name = f"{self.parent.module_sequence}->{module_name}"
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
            if self.parent.timestamp == self.timestamp:
                self._priority = (timestamp,)
            else:
                self._priority = getattr(self.parent, "priority", ()) + (timestamp,)

        return self._priority

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, val):
        self._type = val
        self._hash = None
        self._id = None

    @property
    def _host_size(self):
        """
        Used for sorting events by their host size, so that parent ones (e.g. IP subnets) come first
        """
        if self.host:
            if isinstance(self.host, str):
                # smaller domains should come first
                return len(self.host)
            else:
                try:
                    # bigger IP subnets should come first
                    return -self.host.num_addresses
                except AttributeError:
                    # IP addresses default to 1
                    return 1
        return 0

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
        """
        Event equality is **only** defined between Event instances.

        Equality is based on the event hash (derived from its id). Comparisons to
        non-Event types raise a ValueError to make incorrect comparisons explicit.
        """
        if not is_event(other):
            raise ValueError("Event equality is only defined between Event instances")
        return hash(self) == hash(other)

    def __hash__(self):
        if self._hash is None:
            self._hash = hash(self.id)
        return self._hash

    def __str__(self):
        max_event_len = 80
        d = str(self.data).replace("\n", "\\n")
        return f'{self.type}("{d[:max_event_len]}{("..." if len(d) > max_event_len else "")}", module={self.module}, tags={self.tags})'

    def __repr__(self):
        return str(self)


class SCAN(BaseEvent):
    def _data_human(self):
        return f"{self.data['name']} ({self.data['id']})"

    @property
    def discovery_path(self):
        return []

    @property
    def parent_chain(self):
        return []


class FINISHED(BaseEvent):
    """
    Special signal event to indicate end of scan
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._priority = (999999999999999,)


class DefaultEvent(BaseEvent):
    def sanitize_data(self, data):
        return data


class DictEvent(BaseEvent):
    __slots__ = ["url_extension"]

    def sanitize_data(self, data):
        url = data.get("url", "")
        if url:
            self.parsed_url = self.validators.validate_url_parsed(url)
            # extract url_extension from any dict event with a URL
            url_path = self.parsed_url.path
            if url_path:
                parsed_path_lower = str(url_path).lower()
                extension = get_file_extension(parsed_path_lower)
                if extension:
                    self.url_extension = extension
                    self.add_tag(f"extension-{extension}")
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
            parsed = getattr(self, "parsed_url", None)
            if parsed is not None and parsed.hostname:
                return make_ip_type(parsed.hostname)


class ClosestHostEvent(DictHostEvent):
    # if a host/path/url isn't specified, this event type grabs it from the closest parent
    # inherited by FINDING
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not self.host:
            for parent in self.get_parents(include_self=True):
                # inherit closest URL
                if "url" not in self.data:
                    parent_url = getattr(parent, "parsed_url", None)
                    if parent_url is not None:
                        self.data["url"] = parent_url.geturl()
                # inherit closest path
                if "path" not in self.data and isinstance(parent.data, dict) and not parent.type == "HTTP_RESPONSE":
                    parent_path = parent.data.get("path", None)
                    if parent_path is not None:
                        self.data["path"] = parent_path
                # inherit closest host+port
                if parent.host:
                    self.data["host"] = str(parent.host)
                    self._port = parent.port
                    # we do this to refresh the hash
                    self.data = self.data
                    break
        # die if we still haven't found a host
        if not self.host and not self.data.get("path", ""):
            raise ValueError(f"No host was found in event parents: {self.get_parents()}. Host must be specified!")


class DictPathEvent(DictHostEvent):
    __slots__ = [
        "_data_path",
    ]

    def sanitize_data(self, data):
        data = super().sanitize_data(data)
        new_data = dict(data)
        new_data["path"] = str(new_data["path"])
        file_blobs = getattr(self.scan, "_file_blobs", False)
        folder_blobs = getattr(self.scan, "_folder_blobs", False)
        blob = None
        try:
            self._data_path = Path(data["path"])
            # prepend the scan's home dir if the path is relative
            if not self._data_path.is_absolute():
                self._data_path = self.scan.home / self._data_path
            if self._data_path.is_file():
                self.add_tag("file")
                if file_blobs:
                    with open(self._data_path, "rb") as file:
                        blob = file.read()
            elif self._data_path.is_dir():
                self.add_tag("folder")
                if folder_blobs:
                    blob = self._tar_directory(self._data_path)
        except KeyError:
            pass
        if blob:
            new_data["blob"] = base64.b64encode(blob).decode("utf-8")

        return new_data

    def _tar_directory(self, dir_path):
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w:gz") as tar:
            # Add the entire directory to the tar archive
            tar.add(dir_path, arcname=dir_path.name)
        return tar_buffer.getvalue()


class ASN(DictEvent):
    _always_emit = True
    _quick_emit = True

    def sanitize_data(self, data):
        # accept bare int (from make_event(12345, "ASN")) or dict (from JSON round-trip)
        if isinstance(data, int):
            data = {"asn": data}
        if not isinstance(data, dict) or "asn" not in data:
            raise ValidationError(f"Invalid ASN data (expected dict with 'asn' key): {data}")
        data["asn"] = int(data["asn"])
        return data

    def _data_id(self):
        return str(self.data["asn"])

    def _pretty_string(self):
        return str(self.data["asn"])

    def _data_human(self):
        return f"AS{self.data['asn']}"


class CODE_REPOSITORY(DictHostEvent):
    _always_emit = True

    class _data_validator(BaseModel):
        url: str
        _validate_url = field_validator("url")(validators.validate_url)

    def _pretty_string(self):
        return self.data["url"]

    def _data_human(self):
        return self.data["url"]


class IP_ADDRESS(BaseEvent):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        ip = cached_ip_address(self.data)
        self.add_tag(f"ipv{ip.version}")
        if ip.is_private:
            self.add_tag("private-ip")
        self.dns_resolve_distance = getattr(self.parent, "dns_resolve_distance", 0)

    def sanitize_data(self, data):
        return validators.validate_host(data)

    def _host(self):
        return cached_ip_address(self.data)


class DnsEvent(BaseEvent):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # prevent runaway DNS entries
        self.dns_resolve_distance = 0
        parent = getattr(self, "parent", None)
        module = getattr(self, "module", None)
        module_type = getattr(module, "_type", "")
        parent_module = getattr(parent, "module", None)
        parent_module_type = getattr(parent_module, "_type", "")
        if module_type == "DNS":
            self.dns_resolve_distance = getattr(parent, "dns_resolve_distance", 0)
            if parent_module_type == "DNS":
                self.dns_resolve_distance += 1
        # self.add_tag(f"resolve-distance-{self.dns_resolve_distance}")
        # tag subdomain / domain
        if is_subdomain(self.host):
            self.add_tag("subdomain")
        elif is_domain(self.host):
            self.add_tag("domain")
        # tag private IP
        try:
            if self.host.is_private:
                self.add_tag("private-ip")
        except AttributeError:
            pass


class IP_RANGE(DnsEvent):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.add_tag(f"ipv{self.host.version}")

    def sanitize_data(self, data):
        return str(ipaddress.ip_network(str(data), strict=False))

    def _host(self):
        return ipaddress.ip_network(self.data)


class DNS_NAME(DnsEvent):
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
    # we generally don't care about open ports on affiliates
    _always_emit_tags = ["seed"]

    def sanitize_data(self, data):
        return validators.validate_open_port(data)

    def _host(self):
        host, self._port = split_host_port(self.data)
        return host

    def _words(self):
        if not is_ip(self.host) and not is_ptr(self.host):
            return extract_words(self.host_stem)
        return set()


class OPEN_UDP_PORT(OPEN_TCP_PORT):
    pass


class URL_UNVERIFIED(DictHostEvent):
    _status_code_regex = re.compile(r"^status-(\d{1,3})$")

    __slots__ = [
        "web_spider_distance",
        "num_redirects",
    ]

    def __init__(self, *args, **kwargs):
        self.web_spider_distance = 0
        super().__init__(*args, **kwargs)
        self.num_redirects = getattr(self.parent, "num_redirects", 0)

    def _data_load(self, data):
        # accept a bare URL string and wrap it into a dict
        if isinstance(data, str):
            return {"url": data}
        return data

    def _data_id(self):
        url = self.url

        # remove the querystring for URL/URL_UNVERIFIED events, because we will conditionally add it back in (based on settings)
        if self.__class__.__name__.startswith("URL") and self.scan is not None:
            prefix = url.split("?")[0]

            # consider spider-danger tag when deduping
            if "spider-danger" in self.tags:
                prefix += "spider-danger"

            if not self.scan.config.get("url_querystring_remove", True) and self.parsed_url.query:
                query_dict = parse_qs(self.parsed_url.query)
                if self.scan.config.get("url_querystring_collapse", True):
                    # Only consider parameter names in dedup (collapse values)
                    cleaned_query = "|".join(sorted(query_dict.keys()))
                else:
                    # Consider parameter names and values in dedup
                    cleaned_query = "&".join(
                        f"{key}={','.join(sorted(values))}" for key, values in sorted(query_dict.items())
                    )
                url = f"{prefix}:{self.parsed_url.scheme}:{self.parsed_url.netloc}:{self.parsed_url.path}:{cleaned_query}"
        return url

    def sanitize_data(self, data):
        url = data.get("url", "")
        self.parsed_url = self.validators.validate_url_parsed(url)
        data["url"] = self.parsed_url.geturl()

        # special handling of URL extensions
        if self.parsed_url is not None:
            url_path = self.parsed_url.path
            if url_path:
                parsed_path_lower = str(url_path).lower()
                extension = get_file_extension(parsed_path_lower)
                if extension:
                    self.url_extension = extension
                    self.add_tag(f"extension-{extension}")

        # tag as dir or endpoint
        if str(self.parsed_url.path).endswith("/"):
            self.add_tag("dir")
        else:
            self.add_tag("endpoint")

        return data

    @property
    def pretty_string(self):
        return self.url

    def _data_human(self):
        parts = []
        status = self.http_status
        if status:
            parts.append(f"[{status}]")
        parts.append(self.url)
        if status and str(status).startswith("3"):
            location = self.data.get("redirect_location", "")
            if location:
                parts.append(f"-> {location}")
        else:
            title = self.http_title
            if title:
                parts.append(f"- [{title}]")
        return " ".join(parts)

    def add_tag(self, tag):
        self_url = getattr(self, "parsed_url", "")
        self_host = getattr(self, "host", "")
        # autoincrement web spider distance if the "spider-danger" tag is added
        if tag == "spider-danger" and "spider-danger" not in self.tags and self_url and self_host:
            parent_hosts_and_urls = set()
            for p in self.get_parents():
                # URL_UNVERIFIED events don't count because they haven't been visited yet
                if p.type == "URL_UNVERIFIED":
                    continue
                url = getattr(p, "parsed_url", "")
                parent_hosts_and_urls.add((p.host, url))
            # if there's a URL anywhere in our parent chain that's different from ours but shares our host, we're in dAnGeR
            dangerous_parent = any(
                p_host == self.host and p_url != self_url for p_host, p_url in parent_hosts_and_urls
            )
            if dangerous_parent:
                # increment the web spider distance
                if self.type == "URL_UNVERIFIED":
                    self.web_spider_distance += 1
                if self.is_spider_max:
                    self.add_tag("spider-max")
        super().add_tag(tag)

    @property
    def is_spider_max(self):
        if self.scan:
            depth = url_depth(self.parsed_url)
            if (self.web_spider_distance > self.scan.web_spider_distance) or (depth > self.scan.web_spider_depth):
                return True
        return False

    def with_port(self):
        netloc_with_port = make_netloc(self.host, self.port)
        return self.parsed_url._replace(netloc=netloc_with_port)

    def _words(self):
        first_elem = self.parsed_url.path.lstrip("/").split("/")[0]
        if "." not in first_elem:
            return extract_words(first_elem)
        return set()

    def _host(self):
        return make_ip_type(self.parsed_url.hostname)

    @property
    def http_status(self):
        status_code = self.data.get("status_code", 0)
        if status_code:
            return int(status_code)
        for t in self.tags:
            match = self._status_code_regex.match(t)
            if match:
                return int(match.groups()[0])
        return 0

    @property
    def http_title(self):
        return self.data.get("http_title", "")

    @http_title.setter
    def http_title(self, value):
        self.data["http_title"] = value

    @property
    def redirect_location(self):
        return self.data.get("redirect_location", "")

    @redirect_location.setter
    def redirect_location(self, value):
        self.data["redirect_location"] = value


class URL(URL_UNVERIFIED):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if not self._dummy and not any(t.startswith("status-") for t in self.tags):
            raise ValidationError(
                'Must specify HTTP status tag for URL event, e.g. "status-200". Use URL_UNVERIFIED if the URL is unvisited.'
            )


class STORAGE_BUCKET(URL_UNVERIFIED):
    _always_emit = True
    _suppress_chain_dupes = True

    class _data_validator(BaseModel):
        name: str
        url: str
        _validate_url = field_validator("url")(validators.validate_url)

    def sanitize_data(self, data):
        data = super().sanitize_data(data)
        data["name"] = data["name"].lower()
        return data

    def _data_human(self):
        return f"{self.data['name']} ({self.data['url']})"

    def _words(self):
        return self.data["name"]


class URL_HINT(URL_UNVERIFIED):
    pass


class WEB_PARAMETER(DictHostEvent):
    __slots__ = [
        "envelopes",
    ]

    def _minimize(self):
        super()._minimize()
        if self._module_consumers <= 0:
            self._data.pop("original_value", None)
            self._data.pop("additional_params", None)
            self._data.pop("assigned_cookies", None)
            self._data.pop("same_param_values", None)

    @property
    def children(self):
        # if we have any subparams, raise a new WEB_PARAMETER for each one
        children = []
        envelopes = getattr(self, "envelopes", None)
        if envelopes is not None:
            subparams = sorted(list(self.envelopes.get_subparams()))

            if envelopes.selected_subparam is None:
                current_subparam = subparams[0]
                envelopes.selected_subparam = current_subparam[0]
                if len(subparams) > 1:
                    for subparam, _ in subparams[1:]:
                        clone = self.clone()
                        clone.envelopes = deepcopy(envelopes)
                        clone.envelopes.selected_subparam = subparam
                        clone.parent = self
                        children.append(clone)
        return children

    def sanitize_data(self, data):
        data = super().sanitize_data(data)
        original_value = data.get("original_value", None)
        if original_value is not None:
            try:
                envelopes = BaseEnvelope.detect(original_value)
                setattr(self, "envelopes", envelopes)
            except ValueError as e:
                log.verbose(f"Error detecting envelopes for {self}: {e}")
        return data

    def _data_id(self):
        # dedupe by url:name:param_type
        url = self.data.get("url", "")
        name = self.data.get("name", "")
        param_type = self.data.get("type", "")
        envelopes = getattr(self, "envelopes", "")
        subparam = getattr(envelopes, "selected_subparam", "")

        return f"{url}:{name}:{param_type}:{subparam}"

    def _outgoing_dedup_hash(self, event):
        return hash(
            (
                str(event.host),
                event.data["url"],
                event.data.get("name", ""),
                event.data.get("type", ""),
                event.data.get("envelopes", ""),
            )
        )

    def _url(self):
        return self.data["url"]

    def _data_human(self):
        param_type = self.data.get("type", "")
        name = self.data.get("name", "")
        original_value = self.data.get("original_value", "")
        url = self.data.get("url", "")
        description = self.data.get("description", "")
        additional_params = self.data.get("additional_params", {})
        parts = []
        if param_type:
            parts.append(f"[{param_type}]")
        if original_value:
            parts.append(f"{name}={original_value}")
        else:
            parts.append(name)
        if description:
            parts.append(f"- {description}")
        if additional_params:
            param_names = ", ".join(sorted(additional_params.keys()))
            parts.append(f"Additional Params: [{param_names}]")
        if url:
            parts.append(f"({url})")
        return " ".join(parts)

    def __str__(self):
        max_event_len = 200
        d = str(self.data)
        return f'{self.type}("{d[:max_event_len]}{("..." if len(d) > max_event_len else "")}", module={self.module}, tags={self.tags})'


class EMAIL_ADDRESS(BaseEvent):
    def sanitize_data(self, data):
        return validators.validate_email(data)

    def _host(self):
        data = str(self.data).rsplit("@", 1)[-1]
        host, self._port = split_host_port(data)
        return host

    def _words(self):
        return extract_words(self.host_stem)


class HTTP_RESPONSE(URL_UNVERIFIED):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # count number of consecutive redirects
        self.num_redirects = getattr(self.parent, "num_redirects", 0)
        if str(self.http_status).startswith("3"):
            self.num_redirects += 1

        # Spill body to disk if a per-scan store is available. The body
        # is removed from `_data` so JSON / human renderers don't see it;
        # readers use the `.body` property which lazy-loads from the store.
        # When spill is disabled (no store on the scan), body stays in
        # `_data` and `.body` falls back to reading it from there.
        store = getattr(getattr(self, "scan", None), "body_spill_store", None)
        if store is not None and isinstance(self._data, dict) and "body" in self._data:
            body = self._data.pop("body")
            if isinstance(body, str):
                body_bytes = body.encode("utf-8", errors="replace")
            elif isinstance(body, (bytes, bytearray, memoryview)):
                body_bytes = bytes(body)
            else:
                body_bytes = str(body).encode("utf-8", errors="replace")
            if body_bytes:
                store.write(str(self._uuid), body_bytes)

    @property
    def body(self):
        """
        The HTTP response body as a string.

        With spill enabled, the body lives in the per-scan ``BodySpillStore``
        (LRU cache + disk file). Cache hits are instant; misses re-read
        from disk. After ``_minimize()`` fires the body is gone and this
        property returns ``""``.

        With spill disabled, falls back to ``self._data["body"]``.
        """
        store = getattr(getattr(self, "scan", None), "body_spill_store", None)
        if store is None:
            if isinstance(self._data, dict):
                return self._data.get("body", "") or ""
            return ""
        body_bytes = store.read(str(self._uuid))
        if not body_bytes:
            return ""
        return body_bytes.decode("utf-8", errors="replace")

    def _data_id(self):
        return self.data["method"] + "|" + self.data["url"]

    def sanitize_data(self, data):
        url = data.get("url", "")
        self.parsed_url = self.validators.validate_url_parsed(url)
        data["url"] = self.parsed_url.geturl()

        if not "raw_header" in data:
            raise ValueError("raw_header is required for HTTP_RESPONSE events")

        if "header-dict" not in data:
            header_dict = {}
            for i in data.get("raw_header", "").splitlines():
                if len(i) > 0 and ":" in i:
                    k, v = i.split(":", 1)
                    k = k.strip().lower()
                    v = v.lstrip()
                    if k in header_dict:
                        header_dict[k].append(v)
                    else:
                        header_dict[k] = [v]
            data["header-dict"] = header_dict

        # move URL to the front of the dictionary for visibility
        data = dict(data)
        new_data = {"url": data.pop("url")}
        new_data.update(data)

        return new_data

    def _words(self):
        return set()

    def _pretty_string(self):
        return f"{self.data['hash']['header_mmh3']}:{self.data['hash']['body_mmh3']}"

    def _data_human(self):
        parts = []
        status = self.http_status
        if status:
            parts.append(f"[{status}]")
        method = self.data.get("method", "")
        if method:
            parts.append(method)
        parts.append(self.data.get("url", ""))
        if status and str(status).startswith("3"):
            location = self.redirect_location
            if location:
                parts.append(f"-> {location}")
        else:
            title = self.http_title
            if title:
                parts.append(f"- [{title}]")
        content_length = self.data.get("content_length", 0)
        if content_length:
            parts.append(f"({bytes_to_human(content_length)})")
        return " ".join(parts)

    def _minimize(self):
        super()._minimize()
        if self._module_consumers <= 0:
            store = getattr(getattr(self, "scan", None), "body_spill_store", None)
            if store is not None:
                store.evict_and_delete(str(self._uuid))
            # `body` may still be in _data if spill was disabled at creation
            self._data.pop("body", None)
            self._data.pop("raw_header", None)
            self._data.pop("header", None)
            self._data.pop("cert_info", None)

    @property
    def raw_response(self):
        """
        Formats the status code, headers, and body into a single string formatted as an HTTP/1.1 response.
        """
        raw_header = self.data.get("raw_header", "")
        return f"{raw_header}{self.body}"

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
                location = urljoin(self.parsed_url.geturl(), location)
        return location


class FINDING(ClosestHostEvent):
    _always_emit = True
    _quick_emit = True

    class _stats_class:
        _severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

        def __init__(self):
            self.count = 0
            self.severities = {}

        def increment(self, event):
            self.count += 1
            sev = event.data.get("severity", "UNKNOWN")
            try:
                self.severities[sev] += 1
            except KeyError:
                self.severities[sev] = 1

        def format(self, event_type):
            if not self.severities:
                return f"{event_type}: {self.count}"
            parts = []
            for sev in self._severity_order:
                n = self.severities.get(sev, 0)
                if n:
                    parts.append(f"{n} {sev}")
            for sev, n in sorted(self.severities.items()):
                if sev not in self._severity_order and n:
                    parts.append(f"{n} {sev}")
            return f"{event_type}: {self.count} ({', '.join(parts)})"

    # Standard finding color palette. Single source of truth for every output module.
    # Severity selects the hue (blue, yellow, orange, red, purple); confidence dims it.
    severity_colors_rgb = {
        "INFO": (113, 161, 255),
        "LOW": (255, 215, 0),
        "MEDIUM": (255, 135, 0),
        "HIGH": (255, 0, 0),
        "CRITICAL": (207, 0, 255),
    }
    confidence_brightness = {
        "CONFIRMED": 1.00,
        "HIGH": 0.88,
        "MEDIUM": 0.77,
        "LOW": 0.66,
        "UNKNOWN": 0.55,
    }

    # emoji rendering of the same palette, for chat-based output (Slack, Discord, Teams)
    severity_colors_emoji = {
        "INFO": "🟦",
        "LOW": "🟨",
        "MEDIUM": "🟧",
        "HIGH": "🟥",
        "CRITICAL": "🟪",
    }
    confidence_colors_emoji = {
        "CONFIRMED": "🟣",
        "HIGH": "🔴",
        "MEDIUM": "🟠",
        "LOW": "🟡",
        "UNKNOWN": "⚪",
    }

    # Adaptive Card style names for Microsoft Teams output
    severity_card_colors = {
        "CRITICAL": "Attention",
        "HIGH": "Attention",
        "MEDIUM": "Warning",
        "LOW": "Good",
        "INFO": "Accent",
    }

    def sanitize_data(self, data):
        data = super().sanitize_data(data)
        self.add_tag(f"severity-{data['severity'].lower()}")
        self.add_tag(f"confidence-{data['confidence'].lower()}")
        return data

    class _data_validator(BaseModel):
        host: Optional[str] = None
        severity: str
        name: str
        description: str
        confidence: str
        url: Optional[str] = None
        full_url: Optional[str] = None
        path: Optional[str] = None
        cves: Optional[list[str]] = None
        archive_url: Optional[str] = None
        _validate_url = field_validator("url")(validators.validate_url)
        _validate_host = field_validator("host")(validators.validate_host)
        _validate_severity = field_validator("severity")(validators.validate_severity)
        _validate_confidence = field_validator("confidence")(validators.validate_confidence)

    def _pretty_string(self):
        severity = self.data["severity"]
        confidence = self.data["confidence"]
        description = self.data["description"]

        # Add bold formatting for CONFIRMED confidence
        if confidence == "CONFIRMED":
            confidence_str = f"[\033[1m{confidence}\033[0m]"
        else:
            confidence_str = f"[{confidence}]"
        return f"Severity: [{severity}] Confidence: {confidence_str} {description}"

    def _data_human(self):
        parts = []
        parts.append(f"Severity: [{self.data['severity']}]")
        parts.append(f"Confidence: [{self.data['confidence']}]")
        parts.append(self.data["description"])
        url = self.data.get("url", "")
        if url and url not in self.data["description"]:
            parts.append(f"({url})")
        cves = self.data.get("cves", [])
        if cves:
            parts.append(f"[{', '.join(cves)}]")
        return " ".join(parts)


class TECHNOLOGY(DictHostEvent):
    class _data_validator(BaseModel):
        host: str
        technology: str
        url: Optional[str] = None
        _validate_url = field_validator("url")(validators.validate_url)
        _validate_host = field_validator("host")(validators.validate_host)

    def _sanitize_data(self, data):
        data = super()._sanitize_data(data)
        data["technology"] = data["technology"].lower()
        return data

    def _data_id(self):
        # dedupe by host+port+tech
        tech = self.data.get("technology", "")
        return f"{self.host}:{self.port}:{tech}"

    def _pretty_string(self):
        return self.data["technology"]

    def _data_human(self):
        tech = self.data["technology"]
        url = self.data.get("url", "")
        if url:
            return f"{tech} ({url})"
        return tech


class VIRTUAL_HOST(DictHostEvent):
    class _data_validator(BaseModel):
        host: str
        virtual_host: str
        url: Optional[str] = None
        description: Optional[str] = None
        ip: Optional[str] = None
        _validate_url = field_validator("url")(validators.validate_url)
        _validate_host = field_validator("host")(validators.validate_host)

    def _data_id(self):
        virtual_host = self.data.get("virtual_host", "")
        return f"{self.host}:{virtual_host}"

    def _pretty_string(self):
        virtual_host = self.data.get("virtual_host", "")
        url = self.data.get("url", "")
        description = self.data.get("description", "")
        parts = [virtual_host]
        if url:
            parts.append(f"({url})")
        if description:
            parts.append(description)
        return " ".join(parts)

    def _data_human(self):
        return self._pretty_string()


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

    def _data_human(self):
        protocol = self.data["protocol"]
        port = self.data.get("port")
        banner = self.data.get("banner", "")
        if port:
            result = f"{protocol}/{port}"
        else:
            result = protocol
        if banner:
            result += f" - {banner}"
        return result


class GEOLOCATION(BaseEvent):
    _always_emit = True
    _quick_emit = True

    def _data_human(self):
        country = self.data.get("country_name", "")
        region = self.data.get("region_name", "")
        city = self.data.get("city_name", "") or self.data.get("city", "")
        lat = self.data.get("latitude", "")
        lon = self.data.get("longitude", "")
        location_parts = [p for p in (city, region, country) if p]
        result = ", ".join(location_parts)
        if lat and lon:
            result += f" ({lat}, {lon})"
        return result if result else super()._data_human()


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

    def _data_human(self):
        platform = self.data.get("platform", "")
        profile_name = self.data.get("profile_name", "")
        url = self.data.get("url", "")
        parts = []
        if platform:
            parts.append(f"{platform}:")
        parts.append(profile_name)
        if url:
            parts.append(f"({url})")
        return " ".join(parts)


class WEBSCREENSHOT(DictPathEvent):
    _always_emit = True
    _quick_emit = True

    def _data_human(self):
        return f"{self.data.get('url', '')} Saved to: {self.data.get('path', '')}"


class AZURE_TENANT(DictEvent):
    _always_emit = True
    _quick_emit = True

    def _data_human(self):
        max_domains = 20
        tenant_names = self.data.get("tenant-names", [])
        tenant_id = self.data.get("tenant-id", "")
        domains = self.data.get("domains", [])
        parts = []
        if tenant_names:
            parts.append(", ".join(tenant_names))
        if tenant_id:
            parts.append(f"({tenant_id})")
        if domains:
            if len(domains) <= max_domains:
                parts.append(f"- {', '.join(domains)}")
            else:
                shown = ", ".join(domains[:max_domains])
                hidden = len(domains) - max_domains
                parts.append(f"- {shown} (hiding {hidden} additional domains)")
        return " ".join(parts) if parts else super()._data_human()


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

    def _data_human(self):
        waf = self.data["waf"]
        info = self.data.get("info", "")
        url = self.data.get("url", "")
        if info:
            waf += f" - {info}"
        if url:
            waf += f" ({url})"
        return waf


class FILESYSTEM(DictPathEvent):
    def _data_human(self):
        path = self.data.get("path", "")
        description = self.data.get("magic_description", "")
        if description:
            return f"{path} ({description})"
        return path

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self._data_path.is_file():
            # detect type of file content using magic
            from bbot.core.helpers.libmagic import get_magic_info, get_compression

            try:
                extension, mime_type, description, confidence = get_magic_info(self.data["path"])
                self.data["magic_extension"] = extension
                self.data["magic_mime_type"] = mime_type
                self.data["magic_description"] = description
                self.data["magic_confidence"] = confidence
                # detection compression
                compression = get_compression(mime_type)
                if compression:
                    self.add_tag("compressed")
                    self.add_tag(f"{compression}-archive")
                    self.data["compression"] = compression
                # refresh hash
                self.data = self.data
            except Exception as e:
                log.debug(f"Error detecting file type: {type(e).__name__}: {e}")


class RAW_DNS_RECORD(DictHostEvent, DnsEvent):
    # don't emit raw DNS records for affiliates
    _always_emit_tags = ["seed"]

    def _data_human(self):
        rdtype = self.data.get("type", "")
        host = self.data.get("host", "")
        answer = self.data.get("answer", "")
        return f"{rdtype} {host} -> {answer}"


class MOBILE_APP(DictEvent):
    _always_emit = True

    def _sanitize_data(self, data):
        data = super()._sanitize_data(data)
        if isinstance(data, str):
            data = {"url": data}
        if "url" not in data:
            raise ValidationError("url is required for MOBILE_APP events")
        url = data["url"]
        # parse URL
        try:
            self.parsed_url = urlparse(url)
        except Exception as e:
            raise ValidationError(f"Error parsing URL {url}: {e}")
        if not "id" in data:
            # extract "id" getparam
            params = parse_qs(self.parsed_url.query)
            try:
                _id = params["id"][0]
            except Exception:
                raise ValidationError("id is required for MOBILE_APP events")
            data["id"] = _id
        return data

    def _pretty_string(self):
        return self.data["url"]

    def _data_human(self):
        app_id = self.data.get("id", "")
        url = self.data.get("url", "")
        if app_id and url:
            return f"{app_id} ({url})"
        return url or app_id


def update_event(
    event,
    parent=None,
    context=None,
    module=None,
    scan=None,
    tags=None,
    internal=None,
):
    """
    Updates an existing event object with additional metadata.

    Parameters:
        event (BaseEvent): The event object to update.
        parent (BaseEvent, optional): New parent event.
        context (str, optional): Discovery context to set.
        module (str or BaseModule, optional): Module that discovered the event.
        scan (Scan, optional): BBOT Scan object associated with the event.
        tags (Union[str, List[str]], optional): Tags to merge into the event.
        internal (Any, optional): Marks the event as internal if True.

    Returns:
        BaseEvent: The updated event object.
    """
    if not is_event(event):
        raise ValidationError(f"update_event() expects an Event, got {type(event)}")

    # allow tags to be either a string or an array
    if not tags:
        tags = []
    elif isinstance(tags, str):
        tags = [tags]
    tags = set(tags)

    if scan is not None and not event.scan:
        event.scan = scan
    if module is not None:
        event.module = module
    if parent is not None:
        event.parent = parent
    if context is not None:
        event.discovery_context = context
    if internal is True:
        event.internal = True
    if tags:
        event.tags = tags.union(event.tags)
    return event


def make_event(
    data,
    event_type=None,
    parent=None,
    context=None,
    module=None,
    scan=None,
    tags=None,
    dummy=False,
    internal=None,
):
    """
    Creates and returns a new event object.

    This function serves as a factory for creating new event objects from raw data.
    If you need to modify an existing event, use ``update_event()`` instead.

    Parameters:
        data (Union[str, dict]): The primary data for the event.
        event_type (str, optional): Type of the event, e.g., 'IP_ADDRESS'. Auto-detected if not provided.
        parent (BaseEvent, optional): Parent event leading to this event's discovery.
        context (str, optional): Description of circumstances leading to event's discovery.
        module (str, optional): Module that discovered the event.
        scan (Scan, optional): BBOT Scan object associated with the event.
        scans (List[Scan], optional): Multiple BBOT Scan objects, primarily used for unserialization.
        tags (Union[str, List[str]], optional): Descriptive tags for the event, as a list or a single string.
        dummy (bool, optional): Disables data validations if set to True. Defaults to False.
        internal (Any, optional): Makes the event internal if set to True. Defaults to None.

    Returns:
        BaseEvent: A new event object.

    Raises:
        ValidationError: Raised when there's an error in event data or type sanitization.
    """
    if not data:
        raise ValidationError("No data provided")

    # do not allow passing an existing event here – use update_event() instead
    if is_event(data):
        raise ValidationError(
            "make_event() does not accept an existing event object. Use update_event(event, ...) to modify an event."
        )

    # allow tags to be either a string or an array
    if not tags:
        tags = []
    elif isinstance(tags, str):
        tags = [tags]
    tags = set(tags)

    # if event_type is not provided, autodetect it
    if event_type is None:
        event_seed = EventSeed(data)
        event_type = event_seed.type
        data = event_seed.data
        if not dummy:
            log.debug(f'Autodetected event type "{event_type}" based on data: "{data}"')

    event_type = sys.intern(str(event_type).strip().upper())

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
                data_preview = str(data)[:200] + "..." if len(str(data)) > 200 else str(data)
                raise ValidationError(f'Error sanitizing event data "{data_preview}" for type "{event_type}": {e}')
            data_is_ip = is_ip(data)
            if event_type == "DNS_NAME" and data_is_ip:
                event_type = "IP_ADDRESS"
            elif event_type == "IP_ADDRESS" and not data_is_ip:
                event_type = "DNS_NAME"
    # USERNAME <--> EMAIL_ADDRESS confusion
    if event_type == "USERNAME" and validators.soft_validate(data, "email"):
        event_type = "EMAIL_ADDRESS"
        tags.add("affiliate")
    # Convert single-host IP_RANGE to IP_ADDRESS
    if event_type == "IP_RANGE":
        with suppress(Exception):
            net = ipaddress.ip_network(data, strict=False)
            if net.prefixlen == net.max_prefixlen:
                event_type = "IP_ADDRESS"
                data = net.network_address

    event_class = globals().get(event_type, DefaultEvent)
    return event_class(
        data,
        event_type=event_type,
        parent=parent,
        context=context,
        module=module,
        scan=scan,
        tags=tags,
        _dummy=dummy,
        _internal=internal,
    )


def event_from_json(j):
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
            "tags": j.get("tags", []),
            "context": j.get("discovery_context", None),
            "dummy": True,
        }
        data = j.get("data_json", None)
        if data is None:
            data = j.get("data", None)
        if data is None:
            json_pretty = json.dumps(j, indent=2)
            raise ValueError(f"data or data_json must be provided. JSON: {json_pretty}")
        kwargs["data"] = data
        event = make_event(**kwargs)
        event_uuid = j.get("uuid", None)
        if event_uuid is not None:
            event._uuid = uuid.UUID(event_uuid.split(":")[-1])

        resolved_hosts = j.get("resolved_hosts", [])
        event._resolved_hosts = frozenset(resolved_hosts) if resolved_hosts else None

        http_title = j.get("http_title", "")
        if http_title:
            try:
                event.http_title = http_title
            except AttributeError:
                pass

        # accept both isoformat and unix timestamp
        try:
            event.timestamp = datetime.datetime.fromtimestamp(j["timestamp"], ZoneInfo("UTC"))
        except Exception:
            event.timestamp = datetime.datetime.fromisoformat(j["timestamp"])
        event.scope_distance = j["scope_distance"]
        parent_id = j.get("parent", None)
        if parent_id is not None:
            event._parent_id = parent_id
        parent_uuid = j.get("parent_uuid", None)
        if parent_uuid is not None:
            parent_type, parent_uuid = parent_uuid.split(":", 1)
            event._parent_uuid = parent_type + ":" + str(uuid.UUID(parent_uuid))
        return event
    except KeyError as e:
        raise ValidationError(f"Event missing required field: {e}")


def is_event(e):
    return BaseEvent in e.__class__.__mro__
