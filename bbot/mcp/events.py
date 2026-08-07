"""
Renders scan results by event type.

A BBOT event is a graph node, not a row: a DNS_NAME is a bare hostname, a FINDING
is a dict with a severity and a description, a TECHNOLOGY names software on a
host. Handing all of them back in one generic shape means an agent reads JSON
scaffolding instead of results, and a subdomain scan that found 400 hostnames
returns 400 objects where a list of 400 strings would do.

So each type gets its own renderer, and a pseudotool declares which types its
results are made of (`meta.yields`). Anything without a renderer falls back to
the generic one rather than being dropped.
"""

# How many of one type to render before summarizing the rest.
DEFAULT_LIMIT = 500


def _values(events):
    """The `data` of each event as a string, deduplicated, order preserved."""
    seen, out = set(), []
    for event in events:
        value = event.get("data")
        if isinstance(value, dict):
            value = value.get("url") or value.get("name") or value.get("host") or str(value)
        value = str(value).strip()
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def _render_list(events, limit):
    """Bare values, one per line. For types whose whole content is their data."""
    values = _values(events)
    shown = values[:limit]
    text = "\n".join(shown)
    if len(values) > limit:
        text += f"\n... and {len(values) - limit} more (page with `since`)"
    return text


# Tags that say something about a finding's provenance rather than its content.
# `from-wayback` means the URL came out of an archive, so the vulnerability may
# be on a page that no longer exists -- which changes what the finding is worth.
_PROVENANCE_TAG_HINTS = ("wayback", "paramminer", "spider", "speculative", "affiliate", "http-title")

# Highest first, so a reader sorting by eye starts at the top.
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}


def _render_findings(events, limit):
    """Findings carry the conclusions, so they get the most structure.

    Severity and confidence are read together: a CRITICAL/UNKNOWN is a lead and a
    MEDIUM/CONFIRMED is a result. The description is usually long and is the
    whole point. Tags carry provenance the description does not -- `from-wayback`
    means the finding sits on an archived URL that may no longer exist.
    """

    def sort_key(event):
        data = event.get("data")
        severity = (data.get("severity") if isinstance(data, dict) else None) or "UNKNOWN"
        return _SEVERITY_ORDER.get(str(severity).upper(), 9)

    ordered = sorted(events, key=sort_key)
    blocks = []
    for event in ordered[:limit]:
        data = event.get("data")
        data = data if isinstance(data, dict) else {"description": str(data)}
        severity = str(data.get("severity") or "UNKNOWN").upper()
        confidence = data.get("confidence")
        header = f"[{severity}" + (f"/{str(confidence).upper()}" if confidence else "") + "]"
        where = data.get("url") or data.get("host") or event.get("host") or ""
        block = [f"{header} {where}".strip()]
        description = str(data.get("description") or "").strip()
        if description:
            block.append(f"    {description}")
        tags = [t for t in (event.get("tags") or []) if any(h in str(t).lower() for h in _PROVENANCE_TAG_HINTS)]
        if tags:
            block.append(f"    tags: {', '.join(sorted(tags))}")
        if event.get("module"):
            block.append(f"    found by: {event['module']}")
        if event.get("why"):
            block.append(f"    via: {event['why']}")
        blocks.append("\n".join(block))
    if len(events) > limit:
        blocks.append(f"... and {len(events) - limit} more (page with `since`)")
    return "\n\n".join(blocks)


def _render_web_parameters(events, limit):
    """A discovered parameter is only useful with the URL and the place it goes
    (query string, body, cookie, header)."""
    lines = []
    for event in events[:limit]:
        data = event.get("data")
        data = data if isinstance(data, dict) else {"name": str(data)}
        where = data.get("url") or event.get("host") or ""
        kind = data.get("type") or data.get("param_type") or ""
        lines.append(f"{data.get('name', '')}  {f'({kind}) ' if kind else ''}{where}".strip())
    if len(events) > limit:
        lines.append(f"... and {len(events) - limit} more (page with `since`)")
    return "\n".join(lines)


def _render_technologies(events, limit):
    lines = []
    for event in events[:limit]:
        data = event.get("data")
        data = data if isinstance(data, dict) else {"technology": str(data)}
        host = data.get("url") or data.get("host") or event.get("host") or ""
        lines.append(f"{host}  {data.get('technology', '')}".strip())
    if len(events) > limit:
        lines.append(f"... and {len(events) - limit} more (page with `since`)")
    return "\n".join(lines)


def _render_buckets(events, limit):
    lines = []
    for event in events[:limit]:
        data = event.get("data")
        data = data if isinstance(data, dict) else {"url": str(data)}
        # "exists" and "is readable by anyone" are different answers, and only
        # the tags carry the second one
        open_tag = "OPEN" if any("open" in str(t).lower() for t in event.get("tags") or []) else "private"
        lines.append(f"[{open_tag}] {data.get('url') or data.get('name') or ''}".strip())
    if len(events) > limit:
        lines.append(f"... and {len(events) - limit} more (page with `since`)")
    return "\n".join(lines)


def _render_generic(events, limit):
    """Anything without a dedicated renderer: host, data, and the module."""
    lines = []
    for event in events[:limit]:
        data = event.get("data")
        lines.append(f"{event.get('host') or ''}  {data}  ({event.get('module')})".strip())
    if len(events) > limit:
        lines.append(f"... and {len(events) - limit} more (page with `since`)")
    return "\n".join(lines)


# One renderer per event type. Types absent here use `_render_generic`.
RENDERERS = {
    "DNS_NAME": _render_list,
    "DNS_NAME_UNRESOLVED": _render_list,
    "URL": _render_list,
    "URL_UNVERIFIED": _render_list,
    "EMAIL_ADDRESS": _render_list,
    "OPEN_TCP_PORT": _render_list,
    "OPEN_UDP_PORT": _render_list,
    "IP_ADDRESS": _render_list,
    "CODE_REPOSITORY": _render_list,
    "USERNAME": _render_list,
    "FINDING": _render_findings,
    "WEB_PARAMETER": _render_web_parameters,
    "TECHNOLOGY": _render_technologies,
    "STORAGE_BUCKET": _render_buckets,
}


def known_types():
    return sorted(RENDERERS)


def render(events, limit=DEFAULT_LIMIT):
    """Group events by type and render each group with its own renderer.

    Returns `{event_type: rendered_text}`.
    """
    grouped = {}
    for event in events:
        grouped.setdefault(event.get("type") or "UNKNOWN", []).append(event)
    return {
        event_type: RENDERERS.get(event_type, _render_generic)(group, limit)
        for event_type, group in sorted(grouped.items())
    }
