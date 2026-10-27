"use strict";
// BBOT screenshot gallery. Everything shown comes from scan targets (titles, headers, certificates...), so text only
// ever goes into the page as text: no innerHTML with data in it.

const POLL_MS = 5000;
const LEVEL_NAMES = ["Identical", "Near-identical", "Similar", "Loosely similar"];
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const CARD_MIN_WIDTH = 260;
const GAP = 12;
const SECTION_HEIGHT = 40;
const TABLE_ROW_HEIGHT = 64;
const TABLE_HEAD_HEIGHT = 34;
const FACET_LIMIT = 8;

// ---- data, as the scan writes it ----

const data = {
  generation: null,
  manifest: null,
  chunkRevs: {},
  metaRev: null,
  shots: [],
  hosts: {},
  findings: {},
  version: 0, // bumped on every change, to invalidate derived values
};

// ---- what the viewer has chosen, mirrored in the URL hash ----

const ui = {
  view: "grid",
  group: "visual",
  level: 1,
  sort: "rarest",
  q: "",
  filters: [], // [[field, value]]: OR within a field, AND across fields
  starredOnly: false,
  showHidden: false,
  tableSort: ["url", 1],
};
let terms = []; // ui.q, split
const expanded = new Set();
const facetOpen = new Set();
let compareIds = [];
let detailId = null;
let lightboxId = null;

// ---- triage, kept in this browser per scan ----

const triage = { starred: new Set(), hidden: new Set(), key: null };

function loadTriage(scanId) {
  triage.key = `bbot-gallery:${scanId}`;
  triage.starred = new Set();
  triage.hidden = new Set();
  try {
    const saved = JSON.parse(localStorage.getItem(triage.key) || "{}");
    triage.starred = new Set(saved.starred || []);
    triage.hidden = new Set(saved.hidden || []);
  } catch (e) {
    // private window or blocked storage: triage just won't persist
  }
}

function saveTriage() {
  try {
    localStorage.setItem(
      triage.key,
      JSON.stringify({ starred: [...triage.starred], hidden: [...triage.hidden] }),
    );
  } catch (e) {}
}

// a screenshot is starred or hidden through its URL, or through any group it belongs to
function triageKeys(shot) {
  const keys = [`url:${shot.url}`, `title:${shot.title}`, `tech:${techKey(shot)}`, `cert:${certKey(shot)}`];
  if (shot.groups) shot.groups.forEach((g, i) => keys.push(`v${i}:${g}`));
  return keys;
}
const isStarred = (shot) => triage.starred.size > 0 && info(shot).triageKeys.some((k) => triage.starred.has(k));
const isHidden = (shot) => triage.hidden.size > 0 && info(shot).triageKeys.some((k) => triage.hidden.has(k));

function toggleTriage(set, key) {
  set.has(key) ? set.delete(key) : set.add(key);
  saveTriage();
  refresh();
}

// ---- loading, and keeping up with the scan ----

window.bbotGallery = {
  manifest(manifest) {
    if (manifest.generation !== data.generation) {
      // a different scan wrote here: start over
      Object.assign(data, { generation: manifest.generation, chunkRevs: {}, metaRev: null, shots: [], hosts: {}, findings: {} });
      loadTriage(manifest.scan.id);
    }
    data.manifest = manifest;
    for (const chunk of manifest.chunks) {
      if (data.chunkRevs[chunk.file] !== chunk.rev) {
        data.chunkRevs[chunk.file] = chunk.rev;
        loadScript(`data/${chunk.file}?rev=${chunk.rev}`);
      }
    }
    if (manifest.meta.rev !== data.metaRev) {
      data.metaRev = manifest.meta.rev;
      loadScript(`data/${manifest.meta.file}?rev=${manifest.meta.rev}`);
    }
    renderStatus();
  },
  shots(chunk) {
    for (const shot of chunk.screenshots) data.shots[shot.id] = shot;
    changed();
  },
  meta(meta) {
    data.hosts = meta.hosts;
    data.findings = Object.fromEntries(meta.findings.map((f) => [f.id, f]));
    changed();
  },
};

function loadScript(src) {
  const script = document.createElement("script");
  script.src = src;
  script.onload = script.onerror = () => script.remove();
  document.head.appendChild(script);
}

let changeTimer = null;
function changed() {
  data.version++;
  // chunks arrive together; draw once they have
  clearTimeout(changeTimer);
  changeTimer = setTimeout(refresh, 50);
}

// ---- what each screenshot knows, including its host's data ----

const derivedCache = new Map();

// one pill per severity present, worst first
const severityPills = (d, cls) => d.severities.map(([s, n]) => el("span", { class: `${cls} sev-${s}` }, `${s} ${n}`));

function info(shot) {
  let d = derivedCache.get(shot.id);
  if (d && d.version === data.version) return d;
  const host = data.hosts[shot.host] || {};
  const findings = (host.findings || []).map((id) => data.findings[id]).filter(Boolean);
  const severities = SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length]).filter(([, n]) => n);
  d = {
    version: data.version,
    host,
    findings,
    severity: severities.length ? severities[0][0] : "",
    severities,
    technologies: host.technologies || [],
    clouds: cloudProviders(host.metadata),
    wafs: host.wafs || [],
  };
  d.search = [
    shot.url, shot.requested_url, shot.title, shot.server, shot.status, shot.content_type, shot.redirect,
    shot.js_redirect, shot.ips.join(" "), shot.tags.join(" "), shot.host,
    shot.headers.map((h) => h.join(": ")).join("\n"),
    shot.cert ? [shot.cert.common_name, shot.cert.issuer, (shot.cert.sans || []).join(" ")].join(" ") : "",
    d.technologies.join(" "), d.clouds.join(" "), d.wafs.join(" "),
    findings.map((f) => `${f.name} ${f.description} ${f.severity}`).join("\n"),
    (host.shared_ip_hosts || []).join(" "),
  ].join("\n").toLowerCase();
  derivedCache.set(shot.id, d);
  d.triageKeys = triageKeys(shot);
  d.fields = {};
  return d;
}

function cloudProviders(metadata) {
  const names = new Set();
  for (const entry of Object.values(metadata || {})) {
    for (const name of Object.keys((entry && entry.cloud_providers) || {})) names.add(name);
  }
  return [...names].sort();
}

const techKey = (shot) => info(shot).technologies.join(", ") || "(no technologies)";
const certKey = (shot) =>
  shot.cert ? shot.cert.fingerprint_sha256 || `${shot.cert.issuer} / ${shot.cert.common_name}` : "(no certificate)";

// the values of each field a screenshot can be filtered on
const FIELDS = {
  status: { label: "Status", values: (s) => [String(s.status || "")] },
  severity: { label: "Worst finding", values: (s) => [info(s).severity || "none"] },
  tech: { label: "Technology", values: (s) => info(s).technologies },
  cloud: { label: "Cloud / CDN", values: (s) => info(s).clouds },
  waf: { label: "WAF", values: (s) => info(s).wafs },
  port: { label: "Port", values: (s) => [String(s.port)] },
  server: { label: "Server", values: (s) => (s.server ? [s.server] : []) },
  tag: { label: "Tag", values: (s) => s.tags },
  host: { label: "Host", values: (s) => [s.host] },
  ip: { label: "IP", values: (s) => s.ips },
  title: { label: "Title", values: (s) => (s.title ? [s.title] : []) },
  issuer: { label: "Certificate issuer", values: (s) => (s.cert && s.cert.issuer ? [s.cert.issuer] : []) },
  sha256: { label: "Same screenshot", values: (s) => [s.sha256] },
};
const FACETS = ["status", "severity", "tech", "cloud", "waf", "port", "server", "tag"];

// ---- filtering ----

function fieldValues(shot, field) {
  const fields = info(shot).fields;
  return (fields[field] ||= FIELDS[field].values(shot));
}

// the filtered fields this screenshot doesn't match, or null if it's out regardless (hidden, search...)
function failedFields(shot, wanted) {
  if (!ui.showHidden && isHidden(shot)) return null;
  if (ui.starredOnly && !isStarred(shot)) return null;
  if (terms.length) {
    const text = info(shot).search;
    if (!terms.every((term) => text.includes(term))) return null;
  }
  const failed = [];
  for (const [field, values] of wanted) {
    const have = fieldValues(shot, field);
    if (!values.some((v) => have.includes(v))) failed.push(field);
  }
  return failed;
}

// what passes the filters, and each facet's counts as if that facet weren't filtered, so its other values stay
// pickable: a screenshot failing only one field's filter still counts toward that field's facet
function applyFilters(shots) {
  const wanted = new Map();
  for (const [field, value] of ui.filters) {
    if (FIELDS[field]) wanted.set(field, [...(wanted.get(field) || []), value]);
  }
  const visible = [];
  const counts = Object.fromEntries(FACETS.map((f) => [f, new Map()]));
  for (const shot of shots) {
    const failed = failedFields(shot, wanted);
    if (failed === null || failed.length > 1) continue;
    if (!failed.length) visible.push(shot);
    for (const field of failed.length ? failed : FACETS) {
      if (!counts[field]) continue;
      for (const value of new Set(fieldValues(shot, field))) counts[field].set(value, (counts[field].get(value) || 0) + 1);
    }
  }
  return { visible, counts };
}

const allShots = () => data.shots.filter(Boolean);
const plural = (n, word) => `${n.toLocaleString()} ${word}${n === 1 ? "" : "s"}`;

// ---- grouping ----

function groupKey(shot) {
  switch (ui.group) {
    case "visual":
      return shot.blank ? "blank" : `v${ui.level}:${shot.groups[ui.level]}`;
    case "title":
      return `title:${shot.title}`;
    case "tech":
      return `tech:${techKey(shot)}`;
    case "cert":
      return `cert:${certKey(shot)}`;
    default:
      return `url:${shot.url}`;
  }
}

function groupLabel(key, cover) {
  if (key === "blank") return "Blank pages";
  if (key.startsWith("title:")) return cover.title || "(no title)";
  if (key.startsWith("tech:")) return techKey(cover);
  if (key.startsWith("cert:")) return cover.cert ? `${cover.cert.common_name || "?"} (${cover.cert.issuer || "?"})` : "(no certificate)";
  return "";
}

const severityRank = (shot) => {
  const i = SEVERITIES.indexOf(info(shot).severity);
  return i < 0 ? SEVERITIES.length : i;
};

function buildGroups(shots) {
  const map = new Map();
  for (const shot of shots) {
    const key = groupKey(shot);
    let group = map.get(key);
    if (!group) map.set(key, (group = { key, members: [] }));
    group.members.push(shot);
  }
  const groups = [...map.values()];
  for (const group of groups) {
    // the cover is the shortest URL, usually the site's root
    group.members.sort((a, b) => a.url.length - b.url.length || a.id - b.id);
    group.cover = group.members[0];
    group.label = groupLabel(group.key, group.cover);
    group.severity = Math.min(...group.members.map(severityRank));
  }
  const byHost = (a, b) => a.cover.host.localeCompare(b.cover.host) || a.cover.url.localeCompare(b.cover.url);
  const order = {
    rarest: (a, b) => a.members.length - b.members.length || byHost(a, b),
    largest: (a, b) => b.members.length - a.members.length || byHost(a, b),
    host: byHost,
    severity: (a, b) => a.severity - b.severity || a.members.length - b.members.length || byHost(a, b),
  }[ui.sort];
  groups.sort((a, b) => (a.key === "blank") - (b.key === "blank") || order(a, b));
  return groups;
}

// ---- rendering: everything, and only what's on screen ----

const $ = (id) => document.getElementById(id);
const main = $("main");
const spacer = $("spacer");
let layout = { items: [], height: 0 }; // positioned rows
let layoutSummary = ""; // e.g. "120 groups"
let ordered = []; // screenshots in display order, for stepping through them

function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else if (k === "text") node.textContent = v;
    else node.setAttribute(k, v);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

// only http(s) links; anything else from a target is shown, not linked
const safeHref = (url) => (/^https?:\/\//i.test(url || "") ? url : null);

function refresh() {
  terms = ui.q.toLowerCase().split(/\s+/).filter(Boolean);
  const shots = allShots();
  const { visible, counts } = applyFilters(shots);
  renderFacets(counts);
  renderChips();
  if (ui.view === "table") layoutTable(visible);
  else if (ui.view === "hosts") layoutHosts(visible);
  else layoutGrid(visible);
  $("empty").hidden = visible.length > 0;
  $("empty").textContent = shots.length ? "Nothing matches the current filters." : "No screenshots yet. This page fills in as the scan runs.";
  draw(true);
  renderStatus(visible.length);
  if (detailId !== null && !$("detail").hidden) renderDetail();
  saveHash();
}

function columns() {
  const width = main.clientWidth - 32;
  return Math.max(1, Math.floor((width + GAP) / (CARD_MIN_WIDTH + GAP)));
}

function cardHeight(cols) {
  const width = (main.clientWidth - 32 - GAP * (cols - 1)) / cols;
  return Math.round((width * 10) / 16) + 92;
}

// lays out cells (cards) and sections into rows of known height
function packRows(entries) {
  const cols = columns();
  const rowHeight = cardHeight(cols) + GAP;
  const items = [];
  let y = 12;
  let row = null;
  for (const entry of entries) {
    if (entry.section) {
      items.push({ y, height: SECTION_HEIGHT, section: entry.section });
      y += SECTION_HEIGHT;
      row = null;
      continue;
    }
    if (!row || row.cells.length === cols) {
      row = { y, height: rowHeight, cells: [], cols };
      items.push(row);
      y += rowHeight;
    }
    row.cells.push(entry);
  }
  layout = { items, height: y + 12 };
}

function layoutGrid(visible) {
  const groups = buildGroups(visible);
  const entries = [];
  ordered = [];
  for (const group of groups) {
    if (group.key === "blank") {
      entries.push({ section: { label: `Blank pages (${group.members.length}): nearly all one shade, so they can't be told apart by look` } });
      for (const shot of group.members) {
        entries.push({ shot, group: null });
        ordered.push(shot);
      }
      continue;
    }
    entries.push({ shot: group.cover, group });
    ordered.push(group.cover);
    if (expanded.has(group.key)) {
      for (const shot of group.members.slice(1)) {
        entries.push({ shot, group, member: true });
        ordered.push(shot);
      }
    }
  }
  packRows(entries);
  layoutSummary = plural(groups.length, "group");
}

function layoutHosts(visible) {
  const hosts = new Map();
  for (const shot of visible) {
    if (!hosts.has(shot.host)) hosts.set(shot.host, []);
    hosts.get(shot.host).push(shot);
  }
  const entries = [];
  ordered = [];
  for (const name of [...hosts.keys()].sort()) {
    const shots = hosts.get(name).sort((a, b) => a.url.localeCompare(b.url));
    entries.push({ section: { host: name, shots } });
    for (const shot of shots) {
      entries.push({ shot });
      ordered.push(shot);
    }
  }
  packRows(entries);
  layoutSummary = plural(hosts.size, "host");
}

const TABLE_COLUMNS = [
  ["thumb", "", null],
  ["url", "URL", (s) => s.url],
  ["status", "Status", (s) => s.status],
  ["title", "Title", (s) => s.title],
  ["server", "Server", (s) => s.server],
  ["tech", "Technologies", (s) => info(s).technologies.join(", ")],
  ["severity", "Finding", (s) => severityRank(s)],
  ["ip", "IP", (s) => s.ips.join(", ")],
  ["cloud", "Cloud", (s) => info(s).clouds.join(", ")],
];

function layoutTable(visible) {
  const [key, dir] = ui.tableSort;
  const column = TABLE_COLUMNS.find((c) => c[0] === key) || TABLE_COLUMNS[1];
  ordered = visible
    .map((shot) => [column[2](shot), shot])
    .sort(([x, a], [y, b]) => (x < y ? -1 : x > y ? 1 : a.id - b.id) * dir)
    .map(([, shot]) => shot);
  layout = {
    table: true,
    items: ordered.map((shot, i) => ({ y: TABLE_HEAD_HEIGHT + i * TABLE_ROW_HEIGHT, height: TABLE_ROW_HEIGHT, shot })),
    height: TABLE_HEAD_HEIGHT + ordered.length * TABLE_ROW_HEIGHT,
  };
  layoutSummary = "";
}

let drawn = { from: -1, to: -1 };
function draw(force) {
  const top = main.scrollTop;
  const bottom = top + main.clientHeight;
  const margin = main.clientHeight;
  const items = layout.items;
  // first and last item near the viewport
  let from = 0;
  let lo = 0;
  let hi = items.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (items[mid].y + items[mid].height < top - margin) lo = mid + 1;
    else hi = mid - 1;
  }
  from = lo;
  let to = from;
  while (to < items.length && items[to].y < bottom + margin) to++;
  if (!force && from === drawn.from && to === drawn.to) return;
  drawn = { from, to };
  spacer.style.height = `${layout.height}px`;
  const nodes = [];
  if (layout.table) nodes.push(tableHead());
  for (const item of items.slice(from, to)) {
    if (layout.table) nodes.push(tableRow(item));
    else if (item.section) nodes.push(sectionRow(item));
    else nodes.push(cardRow(item));
  }
  spacer.replaceChildren(...nodes);
}

function cardRow(item) {
  const row = el("div", { class: "row" });
  row.style.top = `${item.y}px`;
  row.style.height = `${item.height - GAP}px`;
  row.style.gridTemplateColumns = `repeat(${item.cols}, minmax(0, 1fr))`;
  row.append(...item.cells.map(card));
  return row;
}

function sectionRow(item) {
  const node = el("div", { class: "section" });
  node.style.top = `${item.y}px`;
  node.style.height = `${item.height}px`;
  const section = item.section;
  if (section.host) {
    const host = data.hosts[section.host] || {};
    const parts = el(
      "span",
      { class: "line" },
      el("span", { class: "host-link", title: "Filter to this host", onclick: () => addFilter("host", section.host) }, section.host),
      el("span", {}, `${section.shots.length} screenshot${section.shots.length === 1 ? "" : "s"}`),
      (host.ips || []).length ? el("span", {}, host.ips.join(", ")) : null,
      (host.technologies || []).slice(0, 6).map((t) => el("span", { class: "tag", onclick: () => addFilter("tech", t) }, t)),
      host.browser_only ? el("span", { class: "tag" }, "browser only") : null,
    );
    node.append(parts);
  } else {
    node.append(section.label);
  }
  return node;
}

function statusClass(status) {
  return `status s${String(status || 0)[0]}`;
}

function card(entry) {
  const { shot, group, member } = entry;
  const d = info(shot);
  const count = group && !member ? group.members.length : 1;
  const node = el("div", {
    class: [
      "card",
      count > 1 ? "stacked" : "",
      member ? "member" : "",
      isHidden(shot) ? "is-hidden" : "",
      compareIds.includes(shot.id) ? "selected" : "",
    ].join(" "),
  });
  const thumb = el(
    "div",
    { class: "thumb", title: "View larger", onclick: () => openLightbox(shot.id) },
    el("img", { src: shot.thumbnail, loading: "lazy", alt: "" }),
  );
  if (count > 1) {
    thumb.append(
      el(
        "span",
        {
          class: "badge count",
          title: expanded.has(group.key) ? "Collapse this group" : "Show every page in this group",
          onclick: (e) => {
            e.stopPropagation();
            expanded.has(group.key) ? expanded.delete(group.key) : expanded.add(group.key);
            refresh();
          },
        },
        `${count} ${expanded.has(group.key) ? "▴" : "▾"}`,
      ),
    );
  }
  if (d.severity) {
    thumb.append(el("div", { class: "badge-row", title: `${d.findings.length} finding(s) on ${shot.host}` }, severityPills(d, "badge")));
  }
  const starKey = group && !member && count > 1 ? group.key : `url:${shot.url}`;
  const actions = el(
    "div",
    { class: `card-actions ${isStarred(shot) ? "on" : ""}` },
    el("button", { class: isStarred(shot) ? "on" : "", title: count > 1 ? "Star this group" : "Star", onclick: (e) => { e.stopPropagation(); toggleTriage(triage.starred, starKey); } }, "★"),
    el("button", { title: count > 1 ? "Hide this group" : "Hide", onclick: (e) => { e.stopPropagation(); toggleTriage(triage.hidden, starKey); } }, isHidden(shot) ? "Unhide" : "Hide"),
    el("button", { title: "Pick for side-by-side compare", onclick: (e) => { e.stopPropagation(); toggleCompare(shot.id); } }, "⇆"),
  );
  thumb.append(actions);
  const caption = el(
    "div",
    { class: "caption" },
    el(
      "div",
      { class: "line" },
      el("span", { class: statusClass(shot.status), title: "Filter by this status", onclick: () => addFilter("status", String(shot.status)) }, shot.status || "?"),
      el("span", { class: "url clickable", title: `${shot.url}\n(details)`, onclick: () => openDetail(shot.id) }, shot.url),
    ),
    el("div", { class: "line" }, el("span", { class: "title", title: shot.title }, (group && !member && group.label) || shot.title || "(no title)")),
    el(
      "div",
      { class: "tags" },
      d.technologies.slice(0, 4).map((t) => el("span", { class: "tag", title: "Filter by this technology", onclick: () => addFilter("tech", t) }, t)),
      d.technologies.length > 4 ? el("span", { class: "tag", title: d.technologies.slice(4).join(", ") }, `+${d.technologies.length - 4}`) : null,
    ),
    el(
      "div",
      { class: "infra" },
      [shot.ips[0], ...d.clouds].filter(Boolean).join(" · ") || " ",
    ),
  );
  node.append(thumb, caption);
  return node;
}

function tableHead() {
  const head = el("div", { class: "table-head" });
  for (const [key, label] of TABLE_COLUMNS) {
    const sorted = ui.tableSort[0] === key;
    head.append(
      el(
        "div",
        {
          class: sorted ? "sorted" : "",
          onclick: () => {
            if (!label) return;
            ui.tableSort = [key, sorted ? -ui.tableSort[1] : 1];
            refresh();
          },
        },
        label + (sorted ? (ui.tableSort[1] > 0 ? " ▴" : " ▾") : ""),
      ),
    );
  }
  return head;
}

function tableRow(item) {
  const shot = item.shot;
  const d = info(shot);
  const row = el(
    "div",
    { class: `table-row ${isHidden(shot) ? "is-hidden" : ""}` },
    el("div", {}, el("img", { src: shot.thumbnail, loading: "lazy", alt: "", onclick: () => openLightbox(shot.id) })),
    el("div", { title: shot.url, class: "clickable", onclick: () => openDetail(shot.id) }, shot.url),
    el("div", {}, el("span", { class: statusClass(shot.status), onclick: () => addFilter("status", String(shot.status)) }, shot.status || "?")),
    el("div", { title: shot.title }, shot.title),
    el("div", { title: shot.server, class: "clickable", onclick: () => shot.server && addFilter("server", shot.server) }, shot.server),
    el("div", { title: d.technologies.join(", ") }, d.technologies.join(", ")),
    el("div", { class: "tags" }, ...severityPills(d, "tag")),
    el("div", { title: shot.ips.join(", ") }, shot.ips.join(", ")),
    el("div", {}, d.clouds.join(", ")),
  );
  row.style.top = `${item.y}px`;
  row.style.height = `${item.height}px`;
  return row;
}

// ---- facets and filter chips ----

function renderFacets(allCounts) {
  const container = $("facets");
  const nodes = [];
  for (const field of FACETS) {
    const counts = allCounts[field];
    if (!counts.size) continue;
    const bySeverity = (v) => (v === "none" ? SEVERITIES.length : SEVERITIES.indexOf(v));
    const sorted = [...counts.entries()].sort((a, b) =>
      field === "severity"
        ? bySeverity(a[0]) - bySeverity(b[0])
        : b[1] - a[1] || String(a[0]).localeCompare(String(b[0])),
    );
    const open = facetOpen.has(field);
    const facet = el("div", { class: "facet" }, el("h3", {}, FIELDS[field].label));
    for (const [value, count] of open ? sorted : sorted.slice(0, FACET_LIMIT)) {
      const active = ui.filters.some(([f, v]) => f === field && v === value);
      facet.append(
        el(
          "div",
          { class: `facet-value ${active ? "active" : ""}`, title: value, onclick: () => (active ? removeFilter(field, value) : addFilter(field, value)) },
          el("span", { class: "label" }, value || "(none)"),
          el("span", { class: "count" }, count.toLocaleString()),
        ),
      );
    }
    if (sorted.length > FACET_LIMIT) {
      facet.append(
        el(
          "div",
          { class: "more", onclick: () => { open ? facetOpen.delete(field) : facetOpen.add(field); refresh(); } },
          open ? "Show fewer" : `Show all ${sorted.length}`,
        ),
      );
    }
    nodes.push(facet);
  }
  container.replaceChildren(...nodes);
}

function renderChips() {
  $("chips").replaceChildren(
    ...ui.filters.map(([field, value]) =>
      el(
        "span",
        { class: "chip removable", title: "Remove this filter", onclick: () => removeFilter(field, value) },
        `${(FIELDS[field] || { label: field }).label}: ${field === "sha256" ? value.slice(0, 12) : value || "(none)"}`,
      ),
    ),
  );
}

function addFilter(field, value) {
  if (!ui.filters.some(([f, v]) => f === field && v === value)) ui.filters.push([field, value]);
  closeOverlays();
  main.scrollTop = 0;
  refresh();
}

function removeFilter(field, value) {
  ui.filters = ui.filters.filter(([f, v]) => !(f === field && v === value));
  refresh();
}

// ---- detail panel ----

function openDetail(id) {
  closeOverlays();
  detailId = id;
  $("detail").hidden = false;
  renderDetail();
}

// the screenshot `delta` places away from `id`, in display order
function step(id, delta) {
  if (!ordered.length) return null;
  const index = ordered.findIndex((s) => s.id === id);
  return ordered[(index + delta + ordered.length) % ordered.length].id;
}

const stepDetail = (delta) => detailId !== null && openDetail(step(detailId, delta));

// ---- lightbox: the screenshot as large as the window allows ----

function openLightbox(id) {
  closeOverlays();
  lightboxId = id;
  const shot = data.shots[id];
  const box = $("lightbox");
  box.hidden = false;
  box.classList.remove("actual-size");
  $("lightbox-img").src = shot.file;
  const index = ordered.findIndex((s) => s.id === id);
  $("lightbox-caption").replaceChildren(
    el("span", { class: statusClass(shot.status) }, shot.status || "?"),
    el("span", { class: "url" }, shot.url),
    el("span", { class: "title" }, shot.title || "(no title)"),
    index >= 0 ? el("span", { class: "position" }, `${index + 1} / ${ordered.length}`) : null,
  );
  $("lightbox-full").href = shot.file;
}

const stepLightbox = (delta) => lightboxId !== null && openLightbox(step(lightboxId, delta));

function kv(rows) {
  const dl = el("dl", { class: "kv" });
  for (const [key, value, onclick] of rows) {
    if (value === undefined || value === null || value === "" || (Array.isArray(value) && !value.length)) continue;
    dl.append(el("dt", {}, key), el("dd", { class: onclick ? "clickable" : "", onclick }, Array.isArray(value) ? value.join(", ") : value));
  }
  return dl;
}

function linkOrText(url) {
  const href = safeHref(url);
  return href ? el("a", { href, target: "_blank", rel: "noopener noreferrer" }, url) : url;
}

function renderDetail() {
  const shot = data.shots[detailId];
  if (!shot) return;
  const d = info(shot);
  const host = d.host;
  $("detail-img").src = shot.file;
  $("detail-full").href = shot.file;
  $("detail-star").classList.toggle("on", isStarred(shot));
  $("detail-star").textContent = isStarred(shot) ? "Starred" : "Star";
  $("detail-hide").textContent = isHidden(shot) ? "Unhide" : "Hide";
  $("detail-compare").classList.toggle("on", compareIds.includes(shot.id));

  const sameFile = allShots().filter((s) => s.sha256 === shot.sha256 && s.id !== shot.id);
  const sameGroup = shot.groups ? allShots().filter((s) => s.groups && s.groups[ui.level] === shot.groups[ui.level] && s.id !== shot.id) : [];
  const body = [
    el("h2", {}, linkOrText(shot.url)),
    el("div", { class: "title" }, shot.title || "(no title)"),
    el("h3", {}, "Page"),
    kv([
      ["Status", shot.status, () => addFilter("status", String(shot.status))],
      ["Requested", shot.requested_url !== shot.url ? shot.requested_url : null],
      ["Server", shot.server, () => shot.server && addFilter("server", shot.server)],
      ["Content type", shot.content_type],
      ["Redirects to", shot.redirect],
      ["Script redirect to", shot.js_redirect],
      ["Screenshot", `${shot.width}×${shot.height}, ${(shot.size / 1024).toFixed(0)} KB${shot.blank ? ", blank" : ""}`],
      ["Taken", new Date(shot.timestamp * 1000).toLocaleString()],
      ["Same screenshot", sameFile.length ? `${sameFile.length} other URL(s)` : null, () => addFilter("sha256", shot.sha256)],
      ["Looks like", sameGroup.length ? `${sameGroup.length} other page(s) at this similarity` : null],
    ]),
    el("h3", {}, "Host"),
    kv([
      ["Host", `${shot.host}:${shot.port}`, () => addFilter("host", shot.host)],
      ["IPs", shot.ips, () => shot.ips[0] && addFilter("ip", shot.ips[0])],
      ["Same IP", host.shared_ip_hosts],
      ["Cloud / CDN", d.clouds, () => d.clouds[0] && addFilter("cloud", d.clouds[0])],
      ["WAF", d.wafs, () => d.wafs[0] && addFilter("waf", d.wafs[0])],
      ["Browser only", host.browser_only ? "yes: only a real browser gets past its challenge" : null],
      ["Scope distance", shot.scope_distance],
    ]),
  ];
  if (d.technologies.length) {
    body.push(el("h3", {}, "Technologies"), el("div", { class: "tags" }, d.technologies.map((t) => el("span", { class: "tag", onclick: () => addFilter("tech", t) }, t))));
  }
  if (d.findings.length) {
    body.push(el("h3", {}, `Findings on ${shot.host} (${d.findings.length})`));
    for (const f of d.findings.slice().sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity))) {
      body.push(
        el(
          "div",
          { class: `finding sev-border-${f.severity}` },
          el("div", {}, el("span", { class: `tag sev-${f.severity}` }, f.severity), " ", el("strong", {}, f.name || "Finding")),
          el("div", {}, f.description),
          f.url ? el("div", { class: "mono" }, linkOrText(f.url)) : null,
        ),
      );
    }
  }
  if (shot.cert) {
    body.push(
      el("h3", {}, "TLS certificate"),
      kv([
        ["Common name", shot.cert.common_name],
        ["Issuer", shot.cert.issuer, () => shot.cert.issuer && addFilter("issuer", shot.cert.issuer)],
        ["Names", shot.cert.sans],
        ["Valid", shot.cert.not_before || shot.cert.not_after ? `${shot.cert.not_before || "?"} to ${shot.cert.not_after || "?"}` : null],
        ["Fingerprint", shot.cert.fingerprint_sha256],
      ]),
    );
  }
  if (shot.headers.length) {
    body.push(el("h3", {}, "Response headers"), kv(shot.headers.map(([k, v]) => [k, v])));
  }
  const dns = host.dns || {};
  if (Object.keys(dns).length) {
    body.push(el("h3", {}, "DNS"), kv(Object.entries(dns).map(([type, records]) => [type, records])));
  }
  if (shot.tags.length) {
    body.push(el("h3", {}, "Tags"), el("div", { class: "tags" }, shot.tags.map((t) => el("span", { class: "tag", onclick: () => addFilter("tag", t) }, t))));
  }
  if (shot.discovery_path.length) {
    body.push(el("h3", {}, "How BBOT found it"), el("ol", { class: "path" }, shot.discovery_path.map((step) => el("li", {}, step))));
  }
  if (Object.keys(host.metadata || {}).length) {
    body.push(el("h3", {}, "Host metadata"), el("pre", { class: "mono" }, JSON.stringify(host.metadata, null, 2)));
  }
  $("detail-body").replaceChildren(...body);
  $("detail-body").scrollTop = 0;
}

// ---- compare ----

function toggleCompare(id) {
  compareIds = compareIds.includes(id) ? compareIds.filter((x) => x !== id) : [...compareIds, id].slice(-2);
  $("compare-button").textContent = `Compare (${compareIds.length}/2)`;
  $("compare-button").disabled = compareIds.length !== 2;
  if (compareIds.length === 2) openCompare();
  else refresh();
}

function hashDistance(a, b) {
  let bits = 0;
  for (let i = 0; i < 16; i++) {
    let x = parseInt(a[i], 16) ^ parseInt(b[i], 16);
    while (x) {
      bits += x & 1;
      x >>= 1;
    }
  }
  return bits;
}

function openCompare() {
  const [a, b] = compareIds.map((id) => data.shots[id]);
  if (!a || !b) return;
  closeOverlays();
  $("compare").hidden = false;
  $("compare-distance").textContent = a.blank || b.blank
    ? "one of them is blank"
    : `differ in ${hashDistance(a.dhash, b.dhash)} of 64 hash bits`;
  const fields = [
    ["URL", (s) => s.url],
    ["Status", (s) => s.status],
    ["Title", (s) => s.title],
    ["Server", (s) => s.server],
    ["IPs", (s) => s.ips.join(", ")],
    ["Technologies", (s) => info(s).technologies.join(", ")],
    ["Certificate", (s) => (s.cert ? `${s.cert.common_name || ""} / ${s.cert.issuer || ""}` : "")],
    ["Size", (s) => `${s.width}×${s.height}`],
  ];
  $("compare-body").replaceChildren(
    ...[a, b].map((shot, i) => {
      const other = i ? a : b;
      const dl = el("dl", { class: "kv" });
      for (const [label, get] of fields) {
        dl.append(el("dt", {}, label), el("dd", { class: String(get(shot)) !== String(get(other)) ? "diff" : "" }, String(get(shot))));
      }
      return el("div", { class: "side" }, el("img", { src: shot.file, alt: "", onclick: () => openDetail(shot.id) }), dl);
    }),
  );
}

function closeOverlays() {
  $("detail").hidden = true;
  $("compare").hidden = true;
  $("lightbox").hidden = true;
  lightboxId = null;
}

// ---- export ----

function exportVisible() {
  // every screenshot that passes the filters, not just group covers
  return applyFilters(allShots()).visible;
}

function download(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = el("a", { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function csvCell(value) {
  const text = String(value ?? "");
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function doExport(kind) {
  const shots = exportVisible();
  const urls = [...new Set(shots.map((s) => s.url))].join("\n") + "\n";
  const name = (data.manifest && data.manifest.scan.name) || "bbot";
  if (kind === "copy") {
    navigator.clipboard.writeText(urls).then(
      () => flashStatus(`Copied ${shots.length} URLs`),
      () => download(`${name}-urls.txt`, urls, "text/plain"),
    );
  } else if (kind === "txt") {
    download(`${name}-urls.txt`, urls, "text/plain");
  } else {
    const header = ["url", "status", "title", "server", "ips", "technologies", "worst_finding", "findings", "cloud", "waf", "starred", "screenshot", "sha256"];
    const lines = [header.join(",")];
    for (const s of shots) {
      const d = info(s);
      lines.push(
        [s.url, s.status, s.title, s.server, s.ips.join(" "), d.technologies.join(" "), d.severity, d.findings.length, d.clouds.join(" "), d.wafs.join(" "), isStarred(s), s.file, s.sha256]
          .map(csvCell)
          .join(","),
      );
    }
    download(`${name}-screenshots.csv`, lines.join("\n") + "\n", "text/csv");
  }
}

// ---- status bar ----

let flash = null;
function flashStatus(text) {
  flash = text;
  renderStatus();
  setTimeout(() => {
    flash = null;
    renderStatus();
  }, 2500);
}

let lastVisible = 0;
function renderStatus(visible) {
  if (visible !== undefined) lastVisible = visible;
  const m = data.manifest;
  if (!m) return;
  $("scan-name").textContent = `BBOT Gallery: ${m.scan.name}`;
  document.title = `${m.scan.name} - BBOT Gallery`;
  const running = !["FINISHED", "ABORTED", "FAILED"].includes(m.scan.status);
  $("live-dot").className = running ? "running" : "";
  const parts = [
    flash,
    `${lastVisible.toLocaleString()} of ${m.total.toLocaleString()} screenshots`,
    layoutSummary,
    `scan ${m.scan.status.toLowerCase()}`,
    `updated ${new Date(m.updated * 1000).toLocaleTimeString()}`,
  ].filter(Boolean);
  $("status-text").textContent = parts.join(" · ");
}

// ---- URL hash: the view can be bookmarked or shared ----

function saveHash() {
  const params = new URLSearchParams();
  if (ui.view !== "grid") params.set("view", ui.view);
  if (ui.group !== "visual") params.set("group", ui.group);
  if (ui.level !== 1) params.set("level", ui.level);
  if (ui.sort !== "rarest") params.set("sort", ui.sort);
  if (ui.q) params.set("q", ui.q);
  for (const [f, v] of ui.filters) params.append("f", `${f}:${v}`);
  if (ui.starredOnly) params.set("starred", "1");
  if (ui.showHidden) params.set("hidden", "1");
  const hash = params.toString();
  if (location.hash.slice(1) !== hash) history.replaceState(null, "", hash ? `#${hash}` : location.pathname);
}

function loadHash() {
  const params = new URLSearchParams(location.hash.slice(1));
  ui.view = params.get("view") || "grid";
  ui.group = params.get("group") || "visual";
  ui.level = Math.min(3, Math.max(0, Number(params.get("level") ?? 1) || 0));
  ui.sort = params.get("sort") || "rarest";
  ui.q = params.get("q") || "";
  ui.filters = params.getAll("f").map((f) => {
    const i = f.indexOf(":");
    return [f.slice(0, i), f.slice(i + 1)];
  }).filter(([f]) => FIELDS[f]);
  ui.starredOnly = params.get("starred") === "1";
  ui.showHidden = params.get("hidden") === "1";
}

function syncControls() {
  $("search").value = ui.q;
  $("group-mode").value = ui.group;
  $("level").value = ui.level;
  $("level-label").textContent = LEVEL_NAMES[ui.level];
  $("level-control").style.display = ui.group === "visual" && ui.view === "grid" ? "" : "none";
  $("sort").value = ui.sort;
  $("starred-only").checked = ui.starredOnly;
  $("show-hidden").checked = ui.showHidden;
  for (const button of document.querySelectorAll(".views button")) button.classList.toggle("active", button.dataset.view === ui.view);
  for (const id of ["group-mode", "sort"]) $(id).parentElement.style.display = ui.view === "grid" ? "" : "none";
}

// ---- wiring ----

function control(id, event, apply) {
  $(id).addEventListener(event, (e) => {
    apply(e.target);
    syncControls();
    main.scrollTop = 0;
    refresh();
  });
}

function init() {
  try {
    const theme = localStorage.getItem("bbot-gallery-theme");
    if (theme) document.documentElement.dataset.theme = theme;
  } catch (e) {}
  loadHash();
  syncControls();

  let searchTimer = null;
  $("search").addEventListener("input", (e) => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      ui.q = e.target.value.trim();
      main.scrollTop = 0;
      refresh();
    }, 150);
  });
  control("group-mode", "change", (t) => (ui.group = t.value));
  control("level", "input", (t) => (ui.level = Number(t.value)));
  control("sort", "change", (t) => (ui.sort = t.value));
  control("starred-only", "change", (t) => (ui.starredOnly = t.checked));
  control("show-hidden", "change", (t) => (ui.showHidden = t.checked));
  for (const button of document.querySelectorAll(".views button")) {
    button.addEventListener("click", () => {
      ui.view = button.dataset.view;
      syncControls();
      main.scrollTop = 0;
      refresh();
    });
  }
  $("theme-toggle").addEventListener("click", () => {
    const theme = document.documentElement.dataset.theme === "light" ? "dark" : "light";
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem("bbot-gallery-theme", theme);
    } catch (e) {}
  });
  $("export-button").addEventListener("click", (e) => {
    e.stopPropagation();
    $("export-menu").hidden = !$("export-menu").hidden;
  });
  for (const button of document.querySelectorAll("[data-export]")) {
    button.addEventListener("click", () => {
      $("export-menu").hidden = true;
      doExport(button.dataset.export);
    });
  }
  document.addEventListener("click", () => ($("export-menu").hidden = true));

  $("detail-close").addEventListener("click", closeOverlays);
  $("detail-prev").addEventListener("click", () => stepDetail(-1));
  $("detail-next").addEventListener("click", () => stepDetail(1));
  $("detail-star").addEventListener("click", () => toggleTriage(triage.starred, `url:${data.shots[detailId].url}`));
  $("detail-hide").addEventListener("click", () => toggleTriage(triage.hidden, `url:${data.shots[detailId].url}`));
  $("detail-compare").addEventListener("click", () => toggleCompare(detailId));
  $("compare-close").addEventListener("click", closeOverlays);
  $("compare-button").addEventListener("click", openCompare);
  $("compare-clear").addEventListener("click", () => {
    compareIds = [];
    $("compare-button").textContent = "Compare (0/2)";
    $("compare-button").disabled = true;
    closeOverlays();
    refresh();
  });
  for (const overlay of [$("detail"), $("compare")]) {
    overlay.addEventListener("click", (e) => e.target === overlay && closeOverlays());
  }
  $("lightbox").addEventListener("click", (e) => {
    if (e.target.id === "lightbox" || e.target.id === "lightbox-stage") closeOverlays();
  });
  // click the image to switch between fitting the window and its actual size
  $("lightbox-img").addEventListener("click", () => $("lightbox").classList.toggle("actual-size"));
  $("lightbox-prev").addEventListener("click", () => stepLightbox(-1));
  $("lightbox-next").addEventListener("click", () => stepLightbox(1));
  $("lightbox-details").addEventListener("click", () => openDetail(lightboxId));
  $("lightbox-close").addEventListener("click", closeOverlays);
  $("detail-img").addEventListener("click", (e) => {
    e.preventDefault();
    openLightbox(detailId);
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeOverlays();
    const inLightbox = !$("lightbox").hidden;
    if (inLightbox && e.key === "ArrowLeft") stepLightbox(-1);
    if (inLightbox && e.key === "ArrowRight") stepLightbox(1);
    if (inLightbox && (e.key === "i" || e.key === "Enter")) openDetail(lightboxId);
    if (!$("detail").hidden && e.key === "ArrowLeft") stepDetail(-1);
    if (!$("detail").hidden && e.key === "ArrowRight") stepDetail(1);
    if (e.key === "/" && document.activeElement !== $("search")) {
      e.preventDefault();
      $("search").focus();
    }
  });
  window.addEventListener("hashchange", () => {
    loadHash();
    syncControls();
    refresh();
  });

  main.addEventListener("scroll", () => requestAnimationFrame(() => draw(false)));
  new ResizeObserver(() => refresh()).observe(main);

  const poll = () => loadScript(`data/manifest.js?t=${Date.now()}`);
  poll();
  setInterval(poll, POLL_MS);
}

init();
