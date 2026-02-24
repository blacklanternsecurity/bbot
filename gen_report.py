import argparse
import ast
import html
import json
import os
import re
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime
from urllib.parse import quote, urlparse


WATCHED_EVENTS = [
    "URL",
    "TECHNOLOGY",
    "FINDING",
    "VULNERABILITY",
    "VHOST",
    "OPEN_TCP_PORT",
    "DNS_NAME",
    "EMAIL_ADDRESS",
    "PROTOCOL",
]
FINDING_TYPES = {"FINDING", "VULNERABILITY"}
OVERVIEW_ONLY_TYPES = {"DNS_NAME", "OPEN_TCP_PORT"}
LEAK_MODULES = {
    "dehashed",
    "leaklookup",
    "leaklookup_hash",
    "gitleaks",
    "noseyparker",
    "trufflehog",
    "ggshield",
    "github_workflows",
}
LEAK_HINTS = ("leak", "secret", "token", "password", "credential", "api key", "private key")

PAIR_RE = re.compile(r"(?:^|[,.]\s+)([A-Za-z][A-Za-z0-9 _./-]{0,40}):\s*\[([^\]]+)\]")
BRACKET_RE = re.compile(r"\[([^\]]+)\]")


def parse_jsonish(raw_value):
    value = raw_value
    # Some BBOT payloads arrive double-encoded (JSON string that contains a Python/JSON object string).
    for _ in range(3):
        if not isinstance(value, str):
            break
        parsed = None
        for parser in (json.loads, ast.literal_eval):
            try:
                candidate = parser(value)
                if candidate != value:
                    parsed = candidate
                    break
            except Exception:
                continue
        if parsed is None:
            break
        value = parsed
    return value


def parse_payload(raw_value, event_type):
    value = parse_jsonish(raw_value)
    if isinstance(value, dict) and event_type in value:
        return value[event_type]
    return value


def parse_host_from_url(url_value):
    if not url_value:
        return ""
    try:
        parsed = urlparse(str(url_value))
        return parsed.netloc or ""
    except Exception:
        return ""


def parse_hostish(value):
    text = str(value or "").strip().lower()
    if not text:
        return ""
    if "://" in text:
        return parse_host_from_url(text).split(":")[0].strip().lower()
    if "/" in text:
        text = text.split("/", 1)[0]
    if ":" in text:
        text = text.split(":", 1)[0]
    return text.strip().lower()


def parse_host_from_email(value):
    text = str(value or "").strip().lower()
    if "@" not in text:
        return ""
    return parse_hostish(text.split("@", 1)[1])


def looks_like_leak_text(text):
    content = str(text or "").lower()
    return any(hint in content for hint in LEAK_HINTS)


def parse_url_parts(url_value):
    text = str(url_value or "").strip()
    if not text:
        return "", None, ""
    try:
        parsed = urlparse(text)
    except Exception:
        return "", None, ""
    host = parse_hostish(parsed.netloc)
    scheme = str(parsed.scheme or "").strip().lower()
    port = parsed.port
    if port is None:
        if scheme == "https":
            port = 443
        elif scheme == "http":
            port = 80
    return host, port, scheme


def guessed_service_for_port(port):
    mapping = {
        21: "ftp",
        22: "ssh",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        143: "imap",
        443: "https",
        3306: "mysql",
        3389: "rdp",
        5432: "postgresql",
        5900: "vnc",
        6379: "redis",
        8080: "http-alt",
        8443: "https-alt",
    }
    return mapping.get(int(port), "")


def apply_technology_payload(event, payload):
    tech = str(payload.get("technology", "")).strip() or str(payload.get("name", "")).strip()
    event["title"] = tech or "Technology"
    desc = str(payload.get("description", "")).strip()
    if desc:
        event["description"] = desc
    else:
        event["description"] = f"Detected technology: {tech}" if tech else "Detected technology signal"
    tech_fields = []
    if tech:
        tech_fields.append(("Technology", tech))
    host_field = str(payload.get("host", "")).strip()
    if host_field:
        tech_fields.append(("Host", host_field))
    url_field = str(payload.get("url", "")).strip()
    if url_field:
        tech_fields.append(("URL", url_field))
        if not event["url"]:
            event["url"] = url_field
    if tech_fields:
        event["fields"] = tech_fields


def parse_tags(raw_tags):
    parsed = parse_jsonish(raw_tags)
    if isinstance(parsed, list):
        return [str(t).strip() for t in parsed if str(t).strip()]
    return []


def parse_timestamp(value):
    text = str(value or "").strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text)
    except Exception:
        return None


def format_duration(start_dt, end_dt):
    if not start_dt or not end_dt:
        return "N/A"
    seconds = int((end_dt - start_dt).total_seconds())
    if seconds < 0:
        return "N/A"
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60
    if hours >= 1:
        return f"{hours}h {minutes}m {secs}s"
    if minutes >= 1:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def truncate_text(value, max_len=320):
    text = str(value or "").strip()
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def clean_field_key(key):
    text = str(key or "").strip()
    text = text.lstrip(" ,.-")
    text = re.sub(r"\s+", " ", text)
    if not text:
        return ""
    lowered = text.lower()
    aliases = {
        "name": "Name",
        "template": "Template",
        "extracted data": "Extracted Data",
        "product type": "Product Type",
        "product": "Product",
        "detecting module": "Detecting Module",
        "vulnerable host": "Vulnerable Host",
        "original event": "Original Event",
        "confidence": "Confidence",
        "signature": "Signature",
        "indicator": "Indicator",
        "trigger": "Trigger",
        "baddns module": "BADDNS Module",
    }
    if lowered in aliases:
        return aliases[lowered]
    return text[:1].upper() + text[1:]


def extract_structured_fields(description):
    desc = str(description or "").strip()
    fields = []

    for key, value in PAIR_RE.findall(desc):
        clean_key = clean_field_key(key.strip().rstrip(",."))
        clean_value = value.strip()
        if clean_key and clean_value:
            fields.append((clean_key, clean_value))

    # Nuclei commonly appends "Extracted Data: [...]" without punctuation prefix.
    extracted_match = re.search(r"Extracted Data:\s*\[([^\]]+)\]", desc, flags=re.IGNORECASE)
    if extracted_match:
        extracted_value = extracted_match.group(1).strip()
        if extracted_value and not any(k.lower() == "extracted data" for k, _ in fields):
            fields.append(("Extracted Data", extracted_value))

    if not fields:
        return desc, []

    # Preserve the original sentence for context but strip duplicate "key: [value]" snippets.
    stripped = PAIR_RE.sub("", desc)
    stripped = re.sub(r"\s+", " ", stripped).strip(" ,.-")
    cleaned_desc = stripped

    return cleaned_desc, fields


def infer_title(event_type, module, payload, description, structured_fields):
    if isinstance(payload, dict):
        explicit = str(payload.get("name", "")).strip()
        if explicit:
            return explicit

    field_map = {k.lower(): v for k, v in structured_fields}

    if "name" in field_map:
        return field_map["name"]

    if module == "nuclei":
        template = field_map.get("template")
        if template:
            return f"Nuclei template: {template}"

    if module == "baddns":
        vuln_host = field_map.get("vulnerable host")
        if not vuln_host:
            match = re.search(r"Vulnerable Host\s*\[([^\]]+)\]", description, flags=re.IGNORECASE)
            vuln_host = match.group(1).strip() if match else ""
        if vuln_host:
            return f"Potential takeover: {vuln_host}"

    if module == "badsecrets":
        ptype = field_map.get("product type")
        if ptype:
            return f"Exposed secret: {ptype}"

    if module == "excavate":
        first = BRACKET_RE.search(description)
        if first:
            return f"Extracted token: {truncate_text(first.group(1), 48)}"

    return event_type


def infer_summary(module, description, structured_fields):
    field_map = {k.lower(): v for k, v in structured_fields}

    if module == "nuclei":
        if field_map.get("name"):
            return field_map["name"]
        if field_map.get("template"):
            return f"Matched nuclei template {field_map['template']}."
    if module == "baddns":
        host = field_map.get("vulnerable host")
        if not host:
            match = re.search(r"Vulnerable Host\s*\[([^\]]+)\]", description, flags=re.IGNORECASE)
            host = match.group(1).strip() if match else ""
        confidence = field_map.get("confidence")
        if host and confidence:
            return f"Potential takeover candidate on {host} (confidence: {confidence})."
        if host:
            return f"Potential takeover candidate on {host}."
    if module == "badsecrets":
        product_type = field_map.get("product type")
        detector = field_map.get("detecting module")
        if product_type and detector:
            return f"Detected {product_type} via {detector}."
        if product_type:
            return f"Detected exposed secret type: {product_type}."

    if description:
        return description
    if structured_fields:
        return "Structured finding details shown below."
    return ""


def normalize_event(row):
    event_type = str(row["type"])
    module = str(row["module"] or "unknown").strip() or "unknown"
    payload = parse_payload(row["data"], event_type)

    event = {
        "type": event_type,
        "module": module,
        "host": "misc",
        "url": "",
        "title": event_type,
        "description": "",
        "severity": "",
        "timestamp": str(row["timestamp"] or ""),
        "tags": parse_tags(row["tags"]),
        "fields": [],
        "port": row["port"] if "port" in row.keys() else None,
        "netloc": str(row["netloc"] or "").strip() if "netloc" in row.keys() else "",
        "asset_value": "",
        "raw": payload,
    }

    row_host = str(row["host"] or "").strip()
    if row_host:
        event["host"] = row_host.lower()

    if isinstance(payload, dict):
        host = str(payload.get("host", "")).strip() or row_host
        url = str(payload.get("url", "")).strip()
        host_from_url = parse_host_from_url(url)

        if not host and host_from_url:
            host = host_from_url

        event["host"] = host.lower() if host else "misc"
        event["url"] = url

        if event_type == "URL":
            data_url = str(payload.get("url", "")).strip() or str(payload.get("data", "")).strip()
            if data_url:
                event["url"] = data_url
                event["title"] = data_url
                event["description"] = data_url
                event["host"] = parse_host_from_url(data_url).lower() or event["host"]
        elif event_type == "TECHNOLOGY":
            apply_technology_payload(event, payload)
        elif event_type == "DNS_NAME":
            dns_name = str(payload.get("DNS_NAME", "")).strip() or str(payload.get("name", "")).strip()
            event["title"] = dns_name or "DNS_NAME"
            event["description"] = dns_name or str(payload)
            event["asset_value"] = dns_name
            dns_host = parse_hostish(dns_name)
            if dns_host:
                event["host"] = dns_host
        elif event_type == "OPEN_TCP_PORT":
            port_data = str(payload.get("OPEN_TCP_PORT", "")).strip()
            event["title"] = port_data or "OPEN_TCP_PORT"
            event["description"] = port_data or str(payload)
            event["asset_value"] = port_data
            host_from_port = parse_hostish(port_data)
            if host_from_port:
                event["host"] = host_from_port
        elif event_type == "PROTOCOL":
            proto = str(payload.get("protocol", "")).strip() or str(payload.get("service", "")).strip()
            banner = str(payload.get("banner", "")).strip()
            event["title"] = proto or "Protocol"
            event["description"] = banner or str(payload)
            event["asset_value"] = proto
        elif event_type == "TECHNOLOGY":
            maybe_obj = parse_jsonish(text)
            if isinstance(maybe_obj, dict):
                apply_technology_payload(event, maybe_obj)
            else:
                event["title"] = "Technology"
                event["description"] = text or "Detected technology signal"
                event["fields"] = [("Technology", text)] if text else []
        elif event_type == "EMAIL_ADDRESS":
            email_value = str(payload.get("EMAIL_ADDRESS", "")).strip() or str(payload.get("email", "")).strip()
            event["type"] = "FINDING"
            event["title"] = "Email Address Discovered"
            event["description"] = email_value or str(payload)
            event["asset_value"] = email_value
            email_host = parse_host_from_email(email_value)
            if email_host:
                event["host"] = email_host
            if email_value:
                event["fields"] = [("Email", email_value)]
        else:
            event["description"] = str(payload.get("description", "")).strip() or str(payload)
            event["severity"] = str(payload.get("severity", "")).strip().upper()
    else:
        text = str(payload).strip()
        event["description"] = text
        if event_type == "URL":
            event["title"] = text
            event["url"] = text
            event["host"] = parse_host_from_url(text).lower() or "misc"
        elif event_type == "DNS_NAME":
            event["title"] = text or "DNS_NAME"
            event["description"] = text
            event["asset_value"] = text
            dns_host = parse_hostish(text)
            if dns_host:
                event["host"] = dns_host
        elif event_type == "OPEN_TCP_PORT":
            event["title"] = text or "OPEN_TCP_PORT"
            event["description"] = text
            event["asset_value"] = text
            host_from_port = parse_hostish(text)
            if host_from_port:
                event["host"] = host_from_port
        elif event_type == "EMAIL_ADDRESS":
            event["type"] = "FINDING"
            event["title"] = "Email Address Discovered"
            event["description"] = text
            event["asset_value"] = text
            email_host = parse_host_from_email(text)
            if email_host:
                event["host"] = email_host
            if text:
                event["fields"] = [("Email", text)]
        else:
            host_from_text = parse_host_from_url(text)
            if host_from_text:
                event["host"] = host_from_text.lower()

    if event["type"] in FINDING_TYPES:
        cleaned, fields = extract_structured_fields(event["description"])
        event["fields"] = fields
        event["description"] = infer_summary(module, cleaned, fields)
        if not event["severity"]:
            for tag in event["tags"]:
                upper = tag.upper()
                if upper in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "INFORMATIONAL"):
                    event["severity"] = upper
                    break
        event["title"] = infer_title(event_type, module, payload, event["description"], fields)
        if event["module"] == "nuclei":
            # Keep concise cards: title already carries the finding identity.
            event["fields"] = [
                (k, v) for k, v in event["fields"] if str(k).strip().lower() not in {"name", "technology"}
            ]

    # Apply nuclei's structured visual treatment to recon events too.
    if event["module"] == "nuclei" and event["type"] not in FINDING_TYPES:
        cleaned, fields = extract_structured_fields(event["description"])
        if fields:
            event["fields"] = fields
            field_map = {k.lower(): v for k, v in fields}
            if field_map.get("name"):
                event["title"] = field_map["name"]
            elif field_map.get("template"):
                event["title"] = f"Nuclei template: {field_map['template']}"
            event["description"] = infer_summary("nuclei", cleaned, fields)

    # Treat leak-related discoveries as vulnerabilities in the report.
    if event["type"] == "FINDING" and (
        event["module"] in LEAK_MODULES
        or (event["module"].startswith("git") and looks_like_leak_text(event.get("description", "")))
        or looks_like_leak_text(event.get("title", ""))
    ):
        event["type"] = "VULNERABILITY"
        if not event["severity"]:
            event["severity"] = "MEDIUM"

    if not event["description"]:
        event["description"] = str(payload)
    if not event["title"]:
        event["title"] = event_type
    if event["host"] and event["host"] != "misc":
        event["host"] = parse_hostish(event["host"]) or event["host"]

    return event


def query_rows(cursor):
    placeholders = ",".join("?" for _ in WATCHED_EVENTS)
    query = (
        f"SELECT type, data, module, timestamp, host, tags, port, netloc "
        f"FROM event WHERE type IN ({placeholders})"
    )
    try:
        cursor.execute(query, WATCHED_EVENTS)
        return cursor.fetchall()
    except sqlite3.Error:
        query = (
            f"SELECT type, data, module, timestamp, host, tags, port, netloc "
            f"FROM Event WHERE type IN ({placeholders})"
        )
        cursor.execute(query, WATCHED_EVENTS)
        return cursor.fetchall()


def get_primary_root(cursor):
    queries = ["SELECT target FROM scan LIMIT 1", "SELECT target FROM Scan LIMIT 1"]
    for query in queries:
        try:
            cursor.execute(query)
            row = cursor.fetchone()
            if not row:
                continue
            target_blob = parse_jsonish(row[0])
            if isinstance(target_blob, dict):
                seeds = target_blob.get("seeds", []) or []
                for seed in seeds:
                    candidate = parse_hostish(seed)
                    if candidate and "." in candidate:
                        return candidate
        except sqlite3.Error:
            continue
    return ""


def host_matches_root(host, root):
    host = parse_hostish(host)
    root = parse_hostish(root)
    if not host or not root:
        return False
    return host == root or host.endswith(f".{root}")


def severity_class(severity):
    severity = (severity or "").upper()
    if severity in ("CRITICAL", "HIGH"):
        return "sev-high"
    if severity in ("MEDIUM",):
        return "sev-medium"
    if severity in ("LOW", "INFO", "INFORMATIONAL"):
        return "sev-low"
    return "sev-unknown"


def safe_href(url):
    value = str(url or "").strip()
    if value.startswith("http://") or value.startswith("https://"):
        return html.escape(value)
    return ""


def canonicalize_url_no_scheme(url):
    value = str(url or "").strip()
    if not value:
        return ""
    try:
        parsed = urlparse(value)
        netloc = (parsed.netloc or "").lower()
        path = parsed.path or "/"
        query = f"?{parsed.query}" if parsed.query else ""
        return f"{netloc}{path}{query}"
    except Exception:
        return value.lower()


def render_fields(fields):
    if not fields:
        return ""
    items = []
    for key, value in fields:
        key_text = html.escape(key)
        key_lower = str(key).strip().lower()
        value_str = str(value or "")
        if key_lower == "extracted data" and len(value_str) > 125:
            preview = html.escape(truncate_text(value_str, 125))
            encoded_full = quote(value_str, safe="")
            value_text = (
                f'{preview} '
                f'<button type="button" class="expand-field-btn" data-full="{encoded_full}">View full</button>'
            )
        else:
            value_text = html.escape(truncate_text(value_str, 500))
        items.append(
            f'<div class="field-row"><span class="f-key">{key_text}</span><span class="f-val">{value_text}</span></div>'
        )
    return f'<div class="field-list">{"".join(items)}</div>'


def render_tags(tags):
    if not tags:
        return ""
    chips = []
    for tag in tags[:8]:
        chips.append(f'<span class="tag-chip">{html.escape(tag)}</span>')
    return f'<div class="tag-list">{"".join(chips)}</div>'


def render_full_details(item):
    if item.get("type") not in FINDING_TYPES:
        return ""

    raw_payload = item.get("raw")
    try:
        if isinstance(raw_payload, (dict, list)):
            raw_text = json.dumps(raw_payload, indent=2, ensure_ascii=False)
        else:
            raw_text = str(raw_payload)
    except Exception:
        raw_text = str(raw_payload)

    meta_rows = []
    host = str(item.get("host", "")).strip()
    if host:
        meta_rows.append(f'<div class="field-row"><span class="f-key">Host</span><span class="f-val">{html.escape(host)}</span></div>')
    url = str(item.get("url", "")).strip()
    if url:
        meta_rows.append(f'<div class="field-row"><span class="f-key">URL</span><span class="f-val">{html.escape(url)}</span></div>')
    module = str(item.get("module", "")).strip()
    if module:
        meta_rows.append(f'<div class="field-row"><span class="f-key">Module</span><span class="f-val">{html.escape(module)}</span></div>')
    ts = str(item.get("timestamp", "")).strip()
    if ts:
        meta_rows.append(f'<div class="field-row"><span class="f-key">Timestamp</span><span class="f-val">{html.escape(ts)}</span></div>')
    tags = ", ".join(str(t) for t in item.get("tags", []) if str(t).strip())
    if tags:
        meta_rows.append(f'<div class="field-row"><span class="f-key">Tags</span><span class="f-val">{html.escape(tags)}</span></div>')

    return (
        '<details class="deep-details">'
        '<summary>Details</summary>'
        f'<div class="field-list">{"".join(meta_rows)}</div>'
        f'<pre class="raw-json">{html.escape(raw_text)}</pre>'
        '</details>'
    )


def render_card(item):
    sev = item.get("severity", "")
    sev_html = ""
    if sev:
        sev_html = f'<span class="sev {severity_class(sev)}">{html.escape(sev)}</span>'

    mod_html = f'<span class="mod-chip">{html.escape(item["module"])}</span>'

    url_html = ""
    href = safe_href(item.get("url"))
    if href:
        url_html = f'<a class="evt-url" href="{href}" target="_blank" rel="noreferrer">{href}</a>'

    time_html = ""
    if item.get("timestamp"):
        time_html = f'<span class="meta-item">{html.escape(item["timestamp"])}</span>'

    description_html = ""
    # Do not render subtitle text for findings/vulnerabilities.
    if item.get("type") not in FINDING_TYPES:
        description_html = f"<p>{html.escape(item['description'])}</p>"

    return f"""
    <article class="event-card type-{html.escape(item['type'].lower())}">
      <header>
        <div class="left-head">
          <span class="evt-type">{html.escape(item['type'])}</span>
          {mod_html}
        </div>
        {sev_html}
      </header>
      <h4>{html.escape(item['title'])}</h4>
      {description_html}
      {render_fields(item.get('fields', []))}
      {url_html}
      {render_tags(item.get('tags', []))}
      {render_full_details(item)}
      <div class="meta-row">{time_html}</div>
    </article>
    """


def render_findings_and_recon(items):
    findings = [i for i in items if i["type"] in FINDING_TYPES]
    recon = [i for i in items if i["type"] not in FINDING_TYPES]

    finding_modules = defaultdict(list)
    for item in findings:
        finding_modules[item["module"]].append(item)

    module_blocks = []
    for module_name in sorted(finding_modules.keys()):
        ordered_items = sorted(
            finding_modules[module_name],
            key=lambda i: (0 if i.get("type") == "VULNERABILITY" else 1, i.get("title", "")),
        )
        cards = "".join(render_card(item) for item in ordered_items)
        module_blocks.append(
            f"""
            <details class="tool-block" open>
              <summary class="tool-head">
                <h3>Found by {html.escape(module_name)}</h3>
                <span>{len(finding_modules[module_name])} items</span>
              </summary>
              <div class="event-grid">{cards}</div>
            </details>
            """
        )

    recon_block = ""
    if recon:
        recon_cards = "".join(render_card(item) for item in recon)
        recon_block = f"""
        <details class="recon-wrap">
          <summary>Recon Events ({len(recon)})</summary>
          <div class="event-grid">{recon_cards}</div>
        </details>
        """

    findings_block = ""
    if module_blocks:
        findings_block = f'<div class="findings-wrap">{"".join(module_blocks)}</div>'
    else:
        findings_block = '<p class="empty-note">No findings or vulnerabilities for this host.</p>'
    return findings_block, recon_block


def related_subdomains(host_base, all_dns_names):
    base = parse_hostish(host_base)
    if not base:
        return []
    children = [d for d in all_dns_names if d.endswith(f".{base}") and d != base]
    return sorted(children)


def related_ports(host_base, ports_by_host_base):
    base = parse_hostish(host_base)
    if not base:
        return {}
    related = {}
    for host, ports in ports_by_host_base.items():
        if host == base or host.endswith(f".{base}"):
            related[host] = sorted(ports)
    return related


def related_port_metadata(host_base, port_metadata_by_host_base):
    base = parse_hostish(host_base)
    if not base:
        return {}
    related = {}
    for host, port_map in port_metadata_by_host_base.items():
        if host == base or host.endswith(f".{base}"):
            related[host] = port_map
    return related


def render_overview_assets(host_label, subdomains, port_metadata_by_host, emails):
    subdomain_items = "".join(f"<li>{html.escape(s)}</li>" for s in subdomains[:250])
    if not subdomain_items:
        subdomain_items = "<li>None discovered</li>"

    port_items = []
    for host in sorted(port_metadata_by_host.keys()):
        for port in sorted(port_metadata_by_host[host].keys()):
            meta = port_metadata_by_host[host][port]
            services = sorted(set(meta.get("services", set())))
            guessed = guessed_service_for_port(port)
            if guessed and guessed not in services:
                services.append(guessed)
            technologies = sorted(set(meta.get("technologies", set())))
            modules = sorted(set(meta.get("modules", set())))
            parts = []
            if services:
                parts.append(f"service: {', '.join(services[:5])}")
            if technologies:
                parts.append(f"tech: {', '.join(technologies[:5])}")
            if modules:
                parts.append(f"source: {', '.join(modules[:4])}")
            suffix = f" - {' | '.join(parts)}" if parts else ""
            port_items.append(f"<li><b>{html.escape(host)}:{int(port)}</b>{html.escape(suffix)}</li>")
    port_html = "".join(port_items[:350]) if port_items else "<li>No open ports captured</li>"
    email_items = "".join(f"<li>{html.escape(e)}</li>" for e in emails[:250]) if emails else "<li>No emails found</li>"

    return f"""
    <div class="asset-grid">
      <section class="asset-card">
        <h3>Subdomains under {html.escape(host_label)}</h3>
        <ul>{subdomain_items}</ul>
      </section>
      <section class="asset-card">
        <h3>Open Ports</h3>
        <ul>{port_html}</ul>
      </section>
      <section class="asset-card">
        <h3>Email Addresses</h3>
        <ul>{email_items}</ul>
      </section>
    </div>
    """


def render_host_section(host_id, host_label, items, host_subdomains, host_port_metadata, host_emails):
    type_counter = Counter(item["type"] for item in items)
    summary_line = " ".join(
        f'<span class="type-pill">{html.escape(t)} <b>{c}</b></span>' for t, c in type_counter.most_common()
    )

    findings_block, recon_block = render_findings_and_recon(items)
    assets_block = render_overview_assets(host_label, host_subdomains, host_port_metadata, host_emails)

    return f"""
    <section id="{host_id}" class="host-section host-panel">
      <div class="host-head">
        <h2>Host Overview: {html.escape(host_label)}</h2>
        <div class="host-summary">{summary_line}</div>
      </div>
      {assets_block}
      {findings_block}
      {recon_block}
    </section>
    """


def render_report(
    scan_name,
    grouped,
    event_counter,
    module_counter,
    primary_root,
    all_dns_names,
    port_metadata_by_host_base,
    emails_by_host,
    duration_text,
):
    host_names = sorted(grouped.keys(), key=lambda x: (x == "misc", x))
    total_events = sum(event_counter.values())
    host_count = len(host_names)

    top_types = "".join(
        f'<span class="kpi-chip">{html.escape(k)} <b>{v}</b></span>' for k, v in event_counter.most_common()
    )
    top_modules = "".join(
        f'<span class="kpi-chip">{html.escape(k)} <b>{v}</b></span>' for k, v in module_counter.most_common(8)
    )

    if primary_root in host_names:
        host_names = [primary_root] + [h for h in host_names if h != primary_root]

    nav_items = []
    host_sections = []

    for idx, host in enumerate(host_names, start=1):
        host_id = f"host-{idx}"
        host_label = host if host != "misc" else "misc / unresolved"
        vuln_count = sum(1 for i in grouped[host] if i.get("type") == "VULNERABILITY")
        finding_count = sum(1 for i in grouped[host] if i.get("type") == "FINDING")
        nav_items.append(
            f'<a href="#{host_id}" class="host-link" data-target="{host_id}">'
            f'<span class="host-label">{html.escape(host_label)}</span>'
            f'<span class="host-badges"><span class="idx-badge idx-vuln">{vuln_count}</span>'
            f'<span class="idx-badge idx-find">{finding_count}</span></span></a>'
        )
        host_base = parse_hostish(host_label)
        host_subdomains = related_subdomains(host_base, all_dns_names)
        host_ports = related_port_metadata(host_base, port_metadata_by_host_base)
        host_emails = sorted(emails_by_host.get(host_base, set()))
        host_sections.append(render_host_section(host_id, host_label, grouped[host], host_subdomains, host_ports, host_emails))

    default_host_id = "host-1"

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>BBOT Report :: {html.escape(scan_name)}</title>
  <link rel="icon" type="image/png" href="/static/guardian_audits_bbot.png">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@500;700&family=Rajdhani:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg:#070b15; --bg2:#0e1931; --card:#0d172b; --line:#1f2f55;
      --txt:#daf5ff; --muted:#7fb0c9; --cyan:#22f7ff; --pink:#ff2ea6; --lime:#98ff5b;
    }}
    * {{ box-sizing:border-box; }}
    body {{
      margin:0; color:var(--txt); background:
      radial-gradient(circle at 10% 10%, rgba(34,247,255,.22) 0%, transparent 33%),
      radial-gradient(circle at 90% 85%, rgba(255,46,166,.24) 0%, transparent 36%),
      linear-gradient(140deg, var(--bg), var(--bg2));
      font-family:'Rajdhani', sans-serif;
    }}
    .report-nav {{
      display:flex; align-items:center; justify-content:space-between; gap:10px;
      border:1px solid var(--line); background:rgba(10,18,33,.78); border-radius:14px;
      padding:10px 12px; margin-bottom:14px;
    }}
    .report-nav .brand {{
      display:flex; align-items:center; gap:10px; color:#d8f3ff; text-decoration:none; font-weight:700;
      letter-spacing:.03em;
    }}
    .report-nav .brand img {{
      width:28px; height:28px; border-radius:8px; border:1px solid var(--line); object-fit:cover;
    }}
    .report-nav .links {{ display:flex; gap:8px; flex-wrap:wrap; }}
    .report-nav .links a {{
      color:#d8f3ff; text-decoration:none; border:1px solid var(--line); border-radius:999px;
      padding:5px 10px; background:rgba(0,0,0,.2); font-weight:600;
    }}
    .report-nav .links a:hover {{ border-color:var(--cyan); color:var(--cyan); }}
    .scan-wrap {{ max-width:1480px; margin:0 auto; padding:24px; }}
    .hero {{
      border:1px solid var(--line); background:rgba(10,18,33,.78); backdrop-filter:blur(7px);
      border-radius:16px; padding:20px 22px; margin-bottom:18px;
      box-shadow:0 0 0 1px rgba(34,247,255,.08), 0 0 45px rgba(255,46,166,.12);
    }}
    .hero-head {{ display:flex; align-items:center; gap:12px; }}
    .report-logo {{
      width:42px; height:42px; border-radius:10px; object-fit:cover;
      border:1px solid var(--line); box-shadow:0 0 18px rgba(34,247,255,.2);
      background:rgba(0,0,0,.2);
    }}
    .hero h1 {{ margin:0 0 6px 0; font-family:'Orbitron', sans-serif; font-size:1.35rem; letter-spacing:.06em; }}
    .hero p {{ margin:0; color:var(--muted); }}
    .kpi-group {{ margin-top:12px; }}
    .kpi-label {{ color:var(--cyan); letter-spacing:.08em; font-size:.78rem; font-weight:700; text-transform:uppercase; }}
    .kpis {{ display:flex; flex-wrap:wrap; gap:8px; margin-top:7px; }}
    .kpi-chip {{ border:1px solid var(--line); border-radius:999px; padding:5px 11px; background:rgba(0,0,0,.22); }}

    .layout {{ display:grid; grid-template-columns:280px 1fr; gap:16px; }}
    .sidebar {{
      position:sticky; top:14px; align-self:start; max-height:calc(100vh - 30px); overflow:auto;
      border:1px solid var(--line); border-radius:14px; padding:12px; background:rgba(10,18,33,.74);
    }}
    .sidebar h3 {{ margin:6px 8px 10px; font-family:'Orbitron', sans-serif; font-size:.92rem; color:var(--cyan); }}
    .host-link {{
      display:flex; justify-content:space-between; align-items:center;
      gap:8px; padding:8px 10px; border-radius:8px; color:var(--txt); text-decoration:none;
      border:1px solid transparent; margin-bottom:4px;
    }}
    .host-label {{ min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
    .host-badges {{ display:flex; align-items:center; gap:6px; flex-shrink:0; }}
    .idx-badge {{
      display:inline-flex; align-items:center; justify-content:center;
      min-width:20px; height:20px; border-radius:999px; font-size:.72rem; font-weight:700;
      border:1px solid;
    }}
    .idx-vuln {{ color:#ffd3de; border-color:#ff2ea6; background:rgba(255,46,166,.22); }}
    .idx-find {{ color:#d6f6ff; border-color:#22f7ff; background:rgba(34,247,255,.2); }}
    .host-link:hover {{ border-color:var(--cyan); background:rgba(34,247,255,.08); }}
    .host-link.active {{ border-color:var(--cyan); background:rgba(34,247,255,.16); }}

    .host-section {{ margin-bottom:18px; border:1px solid var(--line); border-radius:14px; background:rgba(12,20,37,.78); }}
    .host-panel {{ display:none; }}
    .host-panel.active {{ display:block; }}
    .host-head {{ padding:12px 14px; border-bottom:1px solid var(--line); }}
    .host-head h2 {{ margin:0 0 8px; font-size:1.1rem; font-family:'Orbitron', sans-serif; word-break:break-word; }}
    .host-summary {{ display:flex; flex-wrap:wrap; gap:7px; }}
    .type-pill {{ border:1px solid var(--line); border-radius:999px; padding:2px 8px; color:var(--muted); font-size:.9rem; }}

    .asset-grid {{ display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:10px; padding:12px; }}
    .asset-card {{
      border:1px solid var(--line); border-radius:12px; background:rgba(0,0,0,.14);
      padding:10px;
    }}
    .asset-card h3 {{ margin:0 0 8px; color:var(--cyan); font-size:1rem; }}
    .asset-card ul {{ margin:0; padding-left:18px; max-height:220px; overflow:auto; }}
    .asset-card li {{ color:#c6e7f6; margin:0 0 4px; word-break:break-word; }}

    .findings-wrap {{ padding:12px; }}
    .tool-block {{ border:1px solid var(--line); border-radius:12px; margin-bottom:11px; background:rgba(0,0,0,.15); overflow:hidden; }}
    .tool-head {{
      display:flex; justify-content:space-between; align-items:center; padding:10px 12px;
      border-bottom:1px solid var(--line); cursor:pointer; list-style:none;
    }}
    .tool-head::-webkit-details-marker {{ display:none; }}
    .tool-head h3 {{ margin:0; font-size:1rem; color:var(--cyan); }}
    .tool-block:not([open]) .tool-head {{ border-bottom:none; }}

    .event-grid {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(330px,1fr)); gap:10px; padding:12px; }}
    .event-card {{ border:1px solid var(--line); border-radius:11px; padding:10px; background:var(--card); }}
    .event-card header {{ display:flex; justify-content:space-between; align-items:center; margin-bottom:6px; gap:8px; }}
    .left-head {{ display:flex; align-items:center; gap:7px; min-width:0; }}
    .evt-type {{ color:var(--cyan); font-weight:700; letter-spacing:.04em; font-size:.84rem; }}
    .mod-chip {{ border:1px solid #294071; color:#a2d9ff; border-radius:999px; padding:1px 8px; font-size:.75rem; }}
    .event-card h4 {{ margin:0 0 6px; font-size:1rem; color:#ecf8ff; word-break:break-word; }}
    .event-card p {{ margin:0; white-space:pre-wrap; word-break:break-word; color:#b7d9e8; }}
    .evt-url {{ display:block; margin-top:8px; color:var(--lime); text-decoration:none; word-break:break-all; }}
    .evt-url:hover {{ text-decoration:underline; }}

    .field-list {{ margin-top:8px; border:1px solid rgba(127,176,201,.22); border-radius:10px; overflow:hidden; }}
    .field-row {{ display:grid; grid-template-columns:150px 1fr; border-top:1px solid rgba(127,176,201,.18); }}
    .field-row:first-child {{ border-top:none; }}
    .f-key {{ background:rgba(127,176,201,.12); padding:6px 8px; font-weight:700; color:#c5e8ff; }}
    .f-val {{ padding:6px 8px; color:#ddf4ff; word-break:break-word; }}
    .expand-field-btn {{
      margin-left:8px; border:1px solid rgba(127,176,201,.45); background:rgba(16,24,30,.85);
      color:#cdeeff; border-radius:999px; padding:2px 8px; font-size:.72rem; cursor:pointer;
    }}
    .expand-field-btn:hover {{ background:rgba(31,56,72,.95); }}

    .tag-list {{ display:flex; flex-wrap:wrap; gap:6px; margin-top:8px; }}
    .tag-chip {{ border:1px solid #234060; border-radius:999px; padding:1px 7px; font-size:.72rem; color:#8fc2dd; }}

    .meta-row {{ margin-top:8px; color:#7aa7bf; font-size:.82rem; }}
    .meta-item {{ display:inline-block; }}
    .extract-overlay {{
      position:fixed; inset:0; z-index:9999; background:rgba(3,7,9,.62); display:none;
      align-items:flex-start; justify-content:center; padding:16px;
    }}
    .extract-overlay.open {{ display:flex; }}
    .extract-panel {{
      width:min(1200px, 96vw); max-height:60vh; overflow:auto; border:1px solid rgba(127,176,201,.35);
      background:linear-gradient(180deg, rgba(8,15,20,.98), rgba(7,12,16,.98));
      border-radius:14px; box-shadow:0 20px 40px rgba(0,0,0,.55);
    }}
    .extract-head {{
      position:sticky; top:0; display:flex; justify-content:space-between; align-items:center;
      padding:10px 12px; border-bottom:1px solid rgba(127,176,201,.25); background:rgba(9,17,22,.98);
    }}
    .extract-head h3 {{ margin:0; color:#dff2ff; font-size:.95rem; letter-spacing:.08em; text-transform:uppercase; }}
    .extract-close {{
      border:1px solid rgba(127,176,201,.45); background:rgba(16,24,30,.85); color:#cdeeff;
      border-radius:8px; padding:4px 10px; cursor:pointer;
    }}
    .extract-body {{
      margin:0; padding:12px; color:#d6f1ff; font-size:.82rem; line-height:1.45;
      white-space:pre-wrap; word-break:break-word;
    }}

    .recon-wrap {{ border-top:1px solid var(--line); }}
    .recon-wrap > summary {{ cursor:pointer; padding:10px 14px; color:#9ccbe2; font-weight:600; }}
    .deep-details {{ margin-top:8px; border:1px solid rgba(127,176,201,.22); border-radius:10px; }}
    .deep-details > summary {{
      cursor:pointer; padding:6px 8px; color:#9ccbe2; font-weight:700; font-size:.84rem;
      list-style:none;
    }}
    .deep-details > summary::-webkit-details-marker {{ display:none; }}
    .raw-json {{
      margin:8px; padding:8px; border:1px solid rgba(127,176,201,.2); border-radius:8px;
      background:rgba(0,0,0,.22); color:#cdeeff; overflow:auto; max-height:220px; font-size:.78rem;
      white-space:pre-wrap; word-break:break-word;
    }}
    .empty-note {{ color:#9ccbe2; padding:12px; margin:0; }}

    .sev {{ font-size:.75rem; border-radius:999px; padding:2px 7px; border:1px solid; white-space:nowrap; }}
    .sev-high {{ color:#ff6b9a; border-color:#ff2ea6; }}
    .sev-medium {{ color:#ffc36b; border-color:#ff9d2e; }}
    .sev-low {{ color:#8dffb8; border-color:#3cd683; }}
    .sev-unknown {{ color:#a9c0ce; border-color:#597b8f; }}

    @media (max-width: 980px) {{
      .layout {{ grid-template-columns:1fr; }}
      .sidebar {{ position:relative; max-height:none; }}
      .asset-grid {{ grid-template-columns:1fr; }}
      .event-grid {{ grid-template-columns:1fr; }}
      .field-row {{ grid-template-columns:1fr; }}
    }}
  </style>
</head>
<body>
  <main class="scan-wrap">
    <nav class="report-nav">
      <a class="brand" href="/">
        <img src="/static/guardian_audits_bbot.png" alt="Guardian Audits BBOT">
        <span>Guardian Audits BBOT</span>
      </a>
      <div class="links">
        <a href="/">Scan Page</a>
        <a href="/scans">Past Scans</a>
      </div>
    </nav>
    <section class="hero">
      <div class="hero-head">
        <img class="report-logo" src="/static/guardian_audits_bbot.png" alt="Guardian Audits BBOT">
        <h1>BBOT CYBER REPORT :: {html.escape(scan_name)}</h1>
      </div>
      <p>Targets: {host_count} | Events: {total_events} | Duration: {html.escape(duration_text)}</p>
      <div class="kpi-group">
        <div class="kpi-label">Event Types</div>
        <div class="kpis">{top_types}</div>
      </div>
      <div class="kpi-group">
        <div class="kpi-label">Top Modules</div>
        <div class="kpis">{top_modules}</div>
      </div>
    </section>
    <section class="layout">
      <aside class="sidebar">
        <h3>HOST INDEX</h3>
        {''.join(nav_items)}
      </aside>
      <div class="content">{''.join(host_sections)}</div>
    </section>
  </main>
  <div id="extract-overlay" class="extract-overlay" aria-hidden="true">
    <section class="extract-panel">
      <header class="extract-head">
        <h3>Extracted Data</h3>
        <button type="button" id="extract-close" class="extract-close">Close</button>
      </header>
      <pre id="extract-body" class="extract-body"></pre>
    </section>
  </div>
  <script>
    (function() {{
      const panels = Array.from(document.querySelectorAll('.host-panel'));
      const links = Array.from(document.querySelectorAll('.host-link[data-target]'));
      const panelById = Object.fromEntries(panels.map(p => [p.id, p]));
      const overlay = document.getElementById('extract-overlay');
      const overlayBody = document.getElementById('extract-body');
      const overlayClose = document.getElementById('extract-close');

      function activate(id) {{
        let targetId = id;
        if (!panelById[targetId]) targetId = "{default_host_id}";
        panels.forEach(p => p.classList.toggle('active', p.id === targetId));
        links.forEach(l => l.classList.toggle('active', l.dataset.target === targetId));
      }}

      function applyFromHash() {{
        const id = window.location.hash ? window.location.hash.slice(1) : "{default_host_id}";
        activate(id);
      }}

      function closeOverlay() {{
        overlay.classList.remove('open');
        overlay.setAttribute('aria-hidden', 'true');
        overlayBody.textContent = '';
      }}

      document.addEventListener('click', function(evt) {{
        const btn = evt.target.closest('.expand-field-btn');
        if (btn) {{
          const raw = btn.getAttribute('data-full') || '';
          overlayBody.textContent = decodeURIComponent(raw);
          overlay.classList.add('open');
          overlay.setAttribute('aria-hidden', 'false');
          return;
        }}
        if (evt.target === overlay) closeOverlay();
      }});

      overlayClose.addEventListener('click', closeOverlay);
      window.addEventListener('keydown', function(evt) {{
        if (evt.key === 'Escape' && overlay.classList.contains('open')) closeOverlay();
      }});

      window.addEventListener('hashchange', applyFromHash);
      applyFromHash();
    }})();
  </script>
</body>
</html>
"""


def event_fingerprint(event):
    fields = tuple(sorted((str(k), str(v)) for k, v in event.get("fields", [])))
    tags = tuple(sorted(set(str(t) for t in event.get("tags", []))))
    field_map = {str(k).lower(): str(v) for k, v in event.get("fields", [])}

    # Collapse common recon URL duplicates (same host/path, different scheme).
    if event.get("type") == "URL":
        canonical_url = canonicalize_url_no_scheme(event.get("url") or event.get("title"))
        return (
            event.get("type", ""),
            event.get("module", ""),
            event.get("host", ""),
            canonical_url,
        )

    # Nuclei frequently emits the same finding for http/https; collapse by identity.
    if event.get("type") in FINDING_TYPES and event.get("module") == "nuclei":
        template = field_map.get("template", "")
        name = field_map.get("name", "") or event.get("title", "")
        extracted = field_map.get("extracted data", "")
        if template or name:
            return (
                event.get("type", ""),
                event.get("module", ""),
                event.get("host", ""),
                template,
                name,
                extracted,
                event.get("severity", ""),
            )

    return (
        event.get("type", ""),
        event.get("module", ""),
        event.get("host", ""),
        event.get("url", ""),
        event.get("title", ""),
        event.get("description", ""),
        event.get("severity", ""),
        fields,
        tags,
    )


def should_replace_event(existing, candidate):
    if existing.get("type") == "URL" and candidate.get("type") == "URL":
        existing_url = str(existing.get("url", ""))
        candidate_url = str(candidate.get("url", ""))
        if existing_url.startswith("http://") and candidate_url.startswith("https://"):
            return True
    return False


def generate_report(db_path, output_file="web_report.html"):
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        rows = query_rows(cursor)
        primary_root = get_primary_root(cursor)
    except sqlite3.Error as e:
        print(f"Error processing database: {e}")
        return
    finally:
        if conn is not None:
            conn.close()

    grouped = defaultdict(list)
    event_counter = Counter()
    module_counter = Counter()
    all_dns_names = set()
    port_metadata_by_host_base = defaultdict(
        lambda: defaultdict(lambda: {"services": set(), "technologies": set(), "modules": set()})
    )
    emails_by_host = defaultdict(set)
    selected_events = {}

    for row in rows:
        event = normalize_event(row)
        fp = event_fingerprint(event)
        existing = selected_events.get(fp)
        if existing is None or should_replace_event(existing, event):
            selected_events[fp] = event

    for event in selected_events.values():
        event_counter[event["type"]] += 1
        module_counter[event["module"]] += 1
        if event["type"] not in OVERVIEW_ONLY_TYPES:
            grouped[event["host"]].append(event)
        if event["type"] == "DNS_NAME":
            dns_value = parse_hostish(event.get("asset_value", ""))
            if dns_value:
                all_dns_names.add(dns_value)
        elif event["type"] == "OPEN_TCP_PORT":
            host_base = parse_hostish(event["host"])
            if host_base:
                port = event.get("port")
                if isinstance(port, int):
                    port_metadata_by_host_base[host_base][int(port)]["modules"].add(event["module"])
                else:
                    port_match = re.search(r":(\d+)$", str(event.get("asset_value", "")))
                    if port_match:
                        port_metadata_by_host_base[host_base][int(port_match.group(1))]["modules"].add(event["module"])
        elif event["type"] == "URL":
            host_from_url, port_from_url, scheme = parse_url_parts(event.get("url") or event.get("title"))
            if host_from_url and isinstance(port_from_url, int):
                entry = port_metadata_by_host_base[host_from_url][int(port_from_url)]
                entry["modules"].add(event["module"])
                if scheme:
                    entry["services"].add(scheme)
        elif event["type"] == "TECHNOLOGY":
            host_from_url, port_from_url, scheme = parse_url_parts(event.get("url"))
            if host_from_url and isinstance(port_from_url, int):
                entry = port_metadata_by_host_base[host_from_url][int(port_from_url)]
                entry["modules"].add(event["module"])
                if scheme:
                    entry["services"].add(scheme)
                tech = str(event.get("title", "")).strip().lower()
                if tech:
                    entry["technologies"].add(tech)
        elif event["type"] == "PROTOCOL":
            host_base = parse_hostish(event["host"])
            port = event.get("port")
            if host_base and isinstance(port, int):
                entry = port_metadata_by_host_base[host_base][int(port)]
                entry["modules"].add(event["module"])
                proto = str(event.get("asset_value", "")).strip().lower()
                if proto:
                    entry["services"].add(proto)
        email_value = str(event.get("asset_value", "")).strip().lower()
        if "@" in email_value:
            email_host = parse_host_from_email(email_value)
            if email_host:
                emails_by_host[email_host].add(email_value)

    timestamps = [parse_timestamp(e.get("timestamp")) for e in selected_events.values()]
    timestamps = [t for t in timestamps if t is not None]
    if timestamps:
        duration_text = format_duration(min(timestamps), max(timestamps))
    else:
        duration_text = "N/A"

    # Show actionable items first.
    for host in grouped:
        grouped[host].sort(
            key=lambda e: (
                0 if e["type"] in FINDING_TYPES else 1,
                e["module"],
                e["type"],
                e["title"],
            )
        )

    scan_name = os.path.basename(os.path.dirname(os.path.abspath(db_path))) or "BBOT Scan"
    if not primary_root:
        # Fall back to the first resolved host to keep the overview section meaningful.
        primary_root = next((h for h in sorted(grouped.keys()) if h != "misc"), "target")
    html_content = render_report(
        scan_name,
        grouped,
        event_counter,
        module_counter,
        primary_root,
        all_dns_names,
        port_metadata_by_host_base,
        emails_by_host,
        duration_text,
    )

    output_path = output_file or db_path.replace("output.sqlite", "web_report.html")
    output_dir = os.path.dirname(os.path.abspath(output_path))
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate BBOT web report from sqlite output.")
    parser.add_argument("db_path", help="Path to output.sqlite")
    parser.add_argument("output_file", nargs="?", default="web_report.html", help="Output HTML path")
    args = parser.parse_args()
    generate_report(args.db_path, args.output_file)
