### 3.1.0 - Nov 10, 2026
- [https://github.com/blacklanternsecurity/bbot/pull/3584](https://github.com/blacklanternsecurity/bbot/pull/3584)

!!! warning "Check your setup before upgrading"

    3.1 includes changes that can affect existing presets, configs, custom modules, and anything that consumes scan output. Read the [3.0 to 3.1 migration guide](./migration/3.1_breaking_changes.md) before upgrading. The changes most likely to bite:

    - Python 3.11 or newer is required. On 3.10, `pip install --upgrade bbot` stays on 3.0.
    - The `portfilter` module is gone. CDN/WAF port filtering is built in and on by default; remove `portfilter` from presets, and pass `--allow-cdn-ports` to turn the filter off.
    - `module_dirs` only works as a top-level preset key, and BBOT asks before loading each custom module folder. Runs without a terminal need `-y`, and `-S` no longer implies it.
    - Preset `conditions` are read-only: they can warn or abort, but can't modify the preset.
    - dnsdumpster requires an API key, and waf_bypass only tests scan targets by default.
    - lightfuzz now probes WAF-tagged hosts with nowafpls instead of skipping them, and fuzzes one only if the probe gets past the WAF. For the old behavior, set `modules.lightfuzz.avoid_wafs: always` and pass `-em nowafpls`.

#### Highlights

- **DNS brute-forcing moves to BlastDNS:** massdns is gone, and brute-forcing runs through blastdns 2.0 with adaptive rate control. With higher default DNS concurrency, a typical `subdomain-enum` scan finishes in about 40% less time than on 3.0.2, with the same subdomains found ([#3457](https://github.com/blacklanternsecurity/bbot/pull/3457), [#3606](https://github.com/blacklanternsecurity/bbot/pull/3606), [#3612](https://github.com/blacklanternsecurity/bbot/pull/3612))
- **New `--custom-nameservers` flag** for choosing the resolvers BBOT uses for normal resolution ([#3457](https://github.com/blacklanternsecurity/bbot/pull/3457))
- **baddns 2.5.0**, with a new `DELEGATION` submodule that is on by default ([#3457](https://github.com/blacklanternsecurity/bbot/pull/3457))
- **CDN/WAF port filtering in core, on by default** ([#3534](https://github.com/blacklanternsecurity/bbot/pull/3534))
- **Smarter API rate limiting:** `Retry-After` is honored, API keys rotate on a 429, and rate limits no longer count as failures ([#3461](https://github.com/blacklanternsecurity/bbot/pull/3461))
- **Hardened custom module and preset loading** ([#3593](https://github.com/blacklanternsecurity/bbot/pull/3593))
- **New modules:** favicon, js_unpacker, nowafpls, otilabs, scanmalware
- **Python 3.15 supported, Python 3.10 dropped** ([#3474](https://github.com/blacklanternsecurity/bbot/pull/3474))

#### Core & Packaging

- Supported Python is now 3.11 - 3.15 ([#3474](https://github.com/blacklanternsecurity/bbot/pull/3474)).
- CDN/WAF port filtering moved from the `portfilter` module into core and is on by default. Open ports other than 80 and 443 are dropped on hosts tagged `cdn` or `waf`; `--allow-cdn-ports` turns it off ([#3534](https://github.com/blacklanternsecurity/bbot/pull/3534)).
- `api_request` rate limiting overhauled, plus config deprecation support via `Field(deprecated=True)`. Calls made through `api_request` now send a `BBOT/<version>` User-Agent instead of the scan's user agent ([#3461](https://github.com/blacklanternsecurity/bbot/pull/3461)).
- CPE-derived technologies are named by product, with the CPE kept in a new `cpe` field ([#3535](https://github.com/blacklanternsecurity/bbot/pull/3535)).
- In-scope events are no longer tagged `affiliate` ([#3524](https://github.com/blacklanternsecurity/bbot/pull/3524)).
- FINDING text output shows the host when it isn't otherwise present.
- FINDING has an optional `port` for findings that aren't on a URL, such as a TLS or TCP service. It's part of the event's identity and shown as `host:port` in text output, and legba and medusa findings now keep their port ([#3629](https://github.com/blacklanternsecurity/bbot/pull/3629)).
- `HTTP_RESPONSE` events carry `url_extension` ([#3406](https://github.com/blacklanternsecurity/bbot/pull/3406)).
- `ClosestHostEvent` keeps its inherited port, and the port is restored from JSON ([#3462](https://github.com/blacklanternsecurity/bbot/pull/3462)).
- `download()` respects `cache_hrs` in its freshness check ([#3563](https://github.com/blacklanternsecurity/bbot/pull/3563)).
- Fix hostless sort sentinel type mismatch in `Target.add()` ([#3391](https://github.com/blacklanternsecurity/bbot/pull/3391)).
- Version output includes the git commit hash for git checkouts ([#3530](https://github.com/blacklanternsecurity/bbot/pull/3530)).
- `helpers.response_to_json()` removed in favor of `response_to_event_dict()` ([#3473](https://github.com/blacklanternsecurity/bbot/pull/3473)).

#### DNS

- massdns removed. DNS brute-forcing runs through blastdns 2.0, with its own retry budget, a short per-query timeout, and one persistent socket per resolver ([#3457](https://github.com/blacklanternsecurity/bbot/pull/3457)).
- New `dns.brute_max_resolvers` (default 600, `0` for the whole list). Each scan draws that many brute-force resolvers at random, drops the dead ones at startup, and shares the rest across every brute-force run in the scan ([#3612](https://github.com/blacklanternsecurity/bbot/pull/3612)).
- Ordinary DNS concurrency raised and made explicit: `dns.threads` 10 to 50, and a new `dns.max_concurrency` (256) ([#3606](https://github.com/blacklanternsecurity/bbot/pull/3606)).
- New `--custom-nameservers` flag (`dns.nameservers`). An invalid value aborts the scan during prep instead of producing a "completed" scan with zero results ([#3457](https://github.com/blacklanternsecurity/bbot/pull/3457)).
- Resolver diagnostics are reported when brute-force delivery drops ([#3457](https://github.com/blacklanternsecurity/bbot/pull/3457)).
- Already-resolved events skip ahead in dnsresolve's queue ([#3533](https://github.com/blacklanternsecurity/bbot/pull/3533)).
- Fix nested wildcard detection in `is_wildcard` ([#3536](https://github.com/blacklanternsecurity/bbot/pull/3536)).

#### BadDNS

- baddns 2.5.0 ([#3457](https://github.com/blacklanternsecurity/bbot/pull/3457)).
- New `DELEGATION` submodule, enabled by default and in the `baddns` / `baddns-heavy` presets. Checks `_acme-challenge`, `_dmarc` and common DKIM selectors for dangling delegations.
- `NS` gained a lame-delegation finding.
- On-demand TLS platform detection, S3/GCS bucket references in HTML (`references` submodule, in `baddns-heavy`), and a fix for S3 bucket takeover detection.
- Signature refresh: 37 stale signatures removed, 78 updated, and 5 added, plus 14 that suppress NS false positives on registrar and parking nameservers.
- Word matching runs every signature in a single YARA pass per response.

#### Modules

**New:**

- `favicon` - technology detection from favicon hashes ([#3532](https://github.com/blacklanternsecurity/bbot/pull/3532)).
- `js_unpacker` - unpacks source maps, webpack, obfuscator.io, Next.js and Dean Edwards packer JavaScript, and feeds the results back into the scan; in the `js-audit` preset ([#3335](https://github.com/blacklanternsecurity/bbot/pull/3335)).
- `nowafpls` - WAF bypass detection via body padding. lightfuzz, ajaxpro and generic_ssrf pad their payloads on hosts where the bypass is confirmed ([#3336](https://github.com/blacklanternsecurity/bbot/pull/3336)).
- `otilabs` - subdomain enumeration via the OTI Labs Domain Intelligence API ([#3496](https://github.com/blacklanternsecurity/bbot/pull/3496)).
- `scanmalware` - subdomains from ScanMalware's public scan archive. Keyless and opt-in (`-m scanmalware`) ([#3528](https://github.com/blacklanternsecurity/bbot/pull/3528)).

**Removed:** portfilter (replaced by core CDN/WAF port filtering).

**Notable improvements:**

- telerik overhaul: native RAU and DialogHandler crypto, and exploitable RAU detected without uploading a file ([#3333](https://github.com/blacklanternsecurity/bbot/pull/3333)).
- nuclei: nine new template-selection options, new `nuclei-recommended` and `nuclei-new` presets, budget mode fixed (a budget of 10 now means about 15 requests per host, down from 134), and budget mode's template index cached ([#3479](https://github.com/blacklanternsecurity/bbot/pull/3479)). Results are parented to the URL, or the host and port, that nuclei actually scanned, so findings on sibling subdomains or on several ports of one host are no longer merged or mislabeled ([#3629](https://github.com/blacklanternsecurity/bbot/pull/3629)).
- excavate: long redirect detection ([#3481](https://github.com/blacklanternsecurity/bbot/pull/3481)), relative URLs resolved against `<base href>` ([#3522](https://github.com/blacklanternsecurity/bbot/pull/3522)), and hostnames no longer extracted from partway through a hyphenated label ([#3590](https://github.com/blacklanternsecurity/bbot/pull/3590)).
- lightfuzz: positive confirmation required for code-change findings ([#3357](https://github.com/blacklanternsecurity/bbot/pull/3357)), tighter serial error resolution ([#3427](https://github.com/blacklanternsecurity/bbot/pull/3427)), unbounded queue growth from parameter re-discovery fixed ([#3405](https://github.com/blacklanternsecurity/bbot/pull/3405)), baseline URLs counted against spider distance ([#3523](https://github.com/blacklanternsecurity/bbot/pull/3523)), raw Cookie header read in the sqli cookie test ([#3498](https://github.com/blacklanternsecurity/bbot/pull/3498)), and WAF gating comments corrected ([#3608](https://github.com/blacklanternsecurity/bbot/pull/3608)).
- dnsdumpster converted to the authenticated API ([#3458](https://github.com/blacklanternsecurity/bbot/pull/3458)).
- wayback verifies hosts are alive before emitting URLs ([#3359](https://github.com/blacklanternsecurity/bbot/pull/3359)).
- waf_bypass only attempts bypasses against scan targets by default ([#3460](https://github.com/blacklanternsecurity/bbot/pull/3460)).
- crt requests an explicit `/` path, which crt.sh requires ([#3428](https://github.com/blacklanternsecurity/bbot/pull/3428)).
- SQL output modules request sqlalchemy's asyncio extra ([#3505](https://github.com/blacklanternsecurity/bbot/pull/3505)).

#### Performance

- DeepDiff selectively replaced ([#3340](https://github.com/blacklanternsecurity/bbot/pull/3340)), then removed entirely ([#3604](https://github.com/blacklanternsecurity/bbot/pull/3604)).
- Faster `compute_simhash`, with corrected executor placements ([#3331](https://github.com/blacklanternsecurity/bbot/pull/3331)).

#### Security

- Custom module loading hardened: BBOT asks before loading each custom module folder, refuses world-writable folders and files, and refuses custom modules that reuse an existing module name. `config.module_dirs` is deprecated and ignored ([#3593](https://github.com/blacklanternsecurity/bbot/pull/3593)).
- Preset `conditions` are read-only, and module `version` and the global `home` option are validated before they reach an install command ([#3593](https://github.com/blacklanternsecurity/bbot/pull/3593)).
- Symlinks in unarchive output are rejected after extraction ([#3560](https://github.com/blacklanternsecurity/bbot/pull/3560)).
- gitdumper: origin check and depth limit on directory listing ([#3466](https://github.com/blacklanternsecurity/bbot/pull/3466)).
- `dnspython` removed. Nothing imported it, and its old pin held installs below 2.9.0, the fix for GHSA-45c3-73f7-pv4m ([#3610](https://github.com/blacklanternsecurity/bbot/pull/3610)).
- Security dependency updates ([#3557](https://github.com/blacklanternsecurity/bbot/pull/3557)).

#### Dependencies

- blastdns 2.0.3 ([#3612](https://github.com/blacklanternsecurity/bbot/pull/3612)), blasthttp 0.10.1, baddns 2.5.0, badsecrets 1.3.0 ([#3526](https://github.com/blacklanternsecurity/bbot/pull/3526)), cloudcheck 11.2.0 ([#3559](https://github.com/blacklanternsecurity/bbot/pull/3559)), radixtarget 4.3.0 ([#3558](https://github.com/blacklanternsecurity/bbot/pull/3558)), pycryptodome 4.2.0 ([#3542](https://github.com/blacklanternsecurity/bbot/pull/3542), [#3597](https://github.com/blacklanternsecurity/bbot/pull/3597)).
- `deepdiff`, `cachebox` and `orderly-set` removed ([#3604](https://github.com/blacklanternsecurity/bbot/pull/3604)).
- trufflehog 3.97.0 to 3.99.8 ([#3605](https://github.com/blacklanternsecurity/bbot/pull/3605)).

#### Documentation

- New [3.0 to 3.1 migration guide](./migration/3.1_breaking_changes.md) ([#3594](https://github.com/blacklanternsecurity/bbot/pull/3594)), and docs updated for 3.1 ([#3613](https://github.com/blacklanternsecurity/bbot/pull/3613)).

### 3.0.2 - Aug 24, 2026
- [https://github.com/blacklanternsecurity/bbot/pull/3332](https://github.com/blacklanternsecurity/bbot/pull/3332)

#### Highlights

- blasthttp bumped to 0.10.0 ([#3385](https://github.com/blacklanternsecurity/bbot/pull/3385)). `Response.decode_error` is surfaced on `HTTP_RESPONSE` events and tagged `decode-error`, so an undecoded body is never treated as content. `redirect_cookies` now passes through `WebHelper.request()`.
- New `js-audit` preset (`bbot/presets/web/js-audit.yml`). trufflehog streams HTTP bodies via stdin and includes the source URL on findings; its `_module_threads` is bumped to 2.
- Test suite parallelized with pytest-xdist ([#3353](https://github.com/blacklanternsecurity/bbot/pull/3353)).
- Fix: custom YARA rules matching but emitting nothing ([#3374](https://github.com/blacklanternsecurity/bbot/pull/3374)).
- Fix: `docker_pull` crash on a failed registry request.
- Reinstall module deps when they're missing from the environment ([#3338](https://github.com/blacklanternsecurity/bbot/pull/3338)). Adds `packaging` as a runtime dependency.
- Raise process pool `max_tasks_per_child` from 25 to 250 ([#3375](https://github.com/blacklanternsecurity/bbot/pull/3375)).
- CI: pass benchmark refs through env and quote them ([#3354](https://github.com/blacklanternsecurity/bbot/pull/3354)).
- nuclei 3.11.0 to 3.11.1 ([#3367](https://github.com/blacklanternsecurity/bbot/pull/3367)); trufflehog 3.95.9 to 3.97.0 ([#3376](https://github.com/blacklanternsecurity/bbot/pull/3376)).

#### Maintenance

- Dependabot bumps across the uv and github-actions groups: xxhash 4.0.0, ruff 0.16.2, pre-commit 4.6.2, fastapi 0.141.1, uvicorn 0.52.1, lxml 6.1.1, pip 26.2.1, packaging 26.3, tldextract 5.3.2, websockets 16.1.1, mmh3 5.2.1, orjson 3.11.9, regex 2026.7.19, cachetools 7.1.7, pytest-env 1.7.0, pytest-httpserver 1.1.5, actions/setup-python 7.

### 3.0.1 - Jul 21, 2026
- [https://github.com/blacklanternsecurity/bbot/pull/3271](https://github.com/blacklanternsecurity/bbot/pull/3271)

#### Fixes

- Restore cloudcheck tag propagation to URL / OPEN_TCP_PORT children ([#3309](https://github.com/blacklanternsecurity/bbot/pull/3309)). `_minimize()` was wiping `_resolved_hosts` on parent events, starving `dnsresolve` when child events reached it. Cloud tags never made it past the DNS_NAME.
- Fix `virtualhost.finish()` crash when the baseline request returned `None` ([#3273](https://github.com/blacklanternsecurity/bbot/pull/3273)).
- Escape control characters in console output so raw bytes in scan data can't garble the terminal ([#3274](https://github.com/blacklanternsecurity/bbot/pull/3274), closes [#3258](https://github.com/blacklanternsecurity/bbot/issues/3258)).
- Fix stale `baddns` config key in the `kitchen-sink` preset; adds a test that validates every bundled preset ([#3280](https://github.com/blacklanternsecurity/bbot/pull/3280), closes [#3279](https://github.com/blacklanternsecurity/bbot/issues/3279)).
- Fix `openssl_dev_headers` dep check to actually require the header, so minimal images (e.g. `python:3.11-slim`) no longer skip installing `libssl-dev` ([#3282](https://github.com/blacklanternsecurity/bbot/pull/3282), closes [#3272](https://github.com/blacklanternsecurity/bbot/issues/3272)).
- Point API-key docs to `secrets.yml` in the sections that still mentioned `bbot.yml` ([#3283](https://github.com/blacklanternsecurity/bbot/pull/3283), closes [#3270](https://github.com/blacklanternsecurity/bbot/issues/3270)).

#### waf_bypass improvements

- Lower `neighbor_cidr` default from /24 to /28 (module + `waf-bypass` preset).
- Parallelize bypass checks in `finish()` up to 100 by default.
- Distinguish direct vs neighbor bypass candidates in log output.
- Demote non-IP DNS result log from warning to verbose.

#### Tooling updates

- Update `nuclei` to 3.11.0 ([#3275](https://github.com/blacklanternsecurity/bbot/pull/3275)).
- Update `trufflehog` to 3.95.9 ([#3276](https://github.com/blacklanternsecurity/bbot/pull/3276), [#3295](https://github.com/blacklanternsecurity/bbot/pull/3295)).

#### Dependency bumps

`beautifulsoup4` 4.14.3→4.15.0, `cachetools` 6.2.6→7.1.4, `cryptography` 46.0.5→48.0.1, `deepdiff` 8.6.1→9.1.0, `dnspython` 2.7.0→2.8.0, `griffe` 1.15.0→2.1.0, `idna` 3.11→3.18, `lxml` 6.0.2→6.1.0, `maturin` 1.13.3→1.14.1, `mike` 2.1.3→2.2.0, `mkdocs-material` 9.7.1→9.7.7, `mkdocstrings` 0.30.1→1.0.6, `mkdocstrings-python` 2.0.2→2.0.5, `pip` 26.0.1→26.1.2, `pre-commit` 4.5.1→4.6.0, `pydantic` 2.12.5→2.13.4, `pymdown-extensions` 10.20.1→11.0.1, `pytest` 8.4.2→9.1.1, `pytest-cov` 7.0.0→7.1.0, `pytest-env` 1.1.5→1.6.0, `pytest-rerunfailures` 16.1→16.4, `regex` 2026.1.15→2026.7.10, `requests` 2.32.5→2.33.0, `ruff` 0.15.18→0.15.22, `soupsieve` 2.8.3→2.8.4, `starlette` 0.52.1→1.3.1, `tornado` 6.5.4→6.5.7, `urllib3` 2.6.3→2.7.0, `websockets` 15.0.1→16.0, `werkzeug` 3.1.5→3.1.8, `xxhash` 3.6.0→3.8.1, `ansible-runner` 2.4.2→2.4.3, plus `actions/cache` v5→v6.

### 3.0.0 - Jul 8, 2026
- [https://github.com/blacklanternsecurity/bbot/pull/3079](https://github.com/blacklanternsecurity/bbot/pull/3079)

!!! warning "Upgrading from 2.x is not drop-in"

    The CLI, flags, preset syntax, event API, config keys, and module set all changed in backwards-incompatible ways. Read the [2.x to 3.0 migration guide](./migration/3.0_breaking_changes.md) before upgrading. The changes most likely to bite:

    - `-s` now means `--seeds`, not `--silent` (silent moved to `-S`). A script passing `-s` for quiet output will now add a seed instead, with no error.
    - `--whitelist` was retired: `-t/--targets` now defines scope, and `-s/--seeds` drives the scan.
    - `--allow-deadly` was removed, and several flags were renamed (e.g. `noisy` to `loud`).
    - Module options are now pydantic-validated; the legacy options dict hard-fails.
    - Some event types, event attributes, and config keys were renamed or removed.

#### Highlights

- **New HTTP engine (blasthttp):** in-process, rate-limited HTTP replacing the httpx subprocess ([#2992](https://github.com/blacklanternsecurity/bbot/pull/2992), [#3021](https://github.com/blacklanternsecurity/bbot/pull/3021))
- **New DNS engine (BlastDNS)** ([#3042](https://github.com/blacklanternsecurity/bbot/pull/3042))
- **Pydantic config + preset validation:** typos and type errors are caught before a scan starts ([#2486](https://github.com/blacklanternsecurity/bbot/pull/2486), [#3058](https://github.com/blacklanternsecurity/bbot/pull/3058))
- **Scope rework:** clean split between target (scope) and seeds (drivers); `--whitelist` retired ([#2789](https://github.com/blacklanternsecurity/bbot/pull/2789))
- **Findings and Vulnerabilities unified**, with Severity and Confidence ([#2436](https://github.com/blacklanternsecurity/bbot/pull/2436), [#2740](https://github.com/blacklanternsecurity/bbot/pull/2740))
- **asndb:** faster ASN enrichment, plus ASNs usable as scan targets ([#2957](https://github.com/blacklanternsecurity/bbot/pull/2957), [#2741](https://github.com/blacklanternsecurity/bbot/pull/2741))
- **Lightfuzz overhaul:** new SSRF and ESI submodules, far fewer false positives ([#2967](https://github.com/blacklanternsecurity/bbot/pull/2967))
- **Major performance work:** memory and CPU optimizations, bounded DNS caches, HTTP body stripping, string interning ([#2953](https://github.com/blacklanternsecurity/bbot/pull/2953), [#3085](https://github.com/blacklanternsecurity/bbot/pull/3085), [#3088](https://github.com/blacklanternsecurity/bbot/pull/3088))
- **Preset naming / tag standardization** across flags, presets, and event tags ([#2986](https://github.com/blacklanternsecurity/bbot/pull/2986))
- **New modules:** MongoDB / Elastic / Kafka / RabbitMQ / ZeroMQ / NATS outputs, legba, trajan, virtualhost, waf_bypass, dnsspf, Hetzner bucket
- **Modules removed:** wappalyzer, smuggler, digitorus, sitedossier, passivetotal, wpscan

#### Core & Packaging

- Relicensed from GPL-3.0 to AGPL-3.0 ([#2769](https://github.com/blacklanternsecurity/bbot/pull/2769)).
- Packaging moved from Poetry to uv + hatchling, and supported Python is now 3.10 - 3.14 ([#2900](https://github.com/blacklanternsecurity/bbot/pull/2900), [#2731](https://github.com/blacklanternsecurity/bbot/pull/2731)).
- Config values and presets are validated with pydantic before a scan runs, so typos and wrong types fail fast instead of silently doing nothing. The legacy per-module options dict is no longer accepted ([#2486](https://github.com/blacklanternsecurity/bbot/pull/2486), [#3058](https://github.com/blacklanternsecurity/bbot/pull/3058), [#3119](https://github.com/blacklanternsecurity/bbot/pull/3119)).
- Malformed YAML in a config or preset now produces a readable error instead of a stack trace ([#3159](https://github.com/blacklanternsecurity/bbot/pull/3159)).
- New `--reset-config` / `--reset-secrets` to regenerate stale config files ([#3240](https://github.com/blacklanternsecurity/bbot/pull/3240)).

#### Scope & Targeting

- Scope was reworked around a target/seeds split: `-t/--targets` defines scope, `-s/--seeds` supplies the starting events, `--whitelist` is gone, and `--strict-scope` now means "this exact host only" ([#2789](https://github.com/blacklanternsecurity/bbot/pull/2789)).
- ASNs can be used directly as scan targets ([#2741](https://github.com/blacklanternsecurity/bbot/pull/2741)).
- Files can be passed as targets, seeds, or blacklist entries inside presets, and target lists may contain comments ([#2996](https://github.com/blacklanternsecurity/bbot/pull/2996), [#3031](https://github.com/blacklanternsecurity/bbot/pull/3031)).

#### HTTP & Web

- All web traffic now runs in-process through one shared, rate-limited client (blasthttp) instead of a separate httpx subprocess ([#2992](https://github.com/blacklanternsecurity/bbot/pull/2992), [#3021](https://github.com/blacklanternsecurity/bbot/pull/3021)).
- HTTP wildcard/catch-all host detection cuts false positives on servers that answer every request ([#3164](https://github.com/blacklanternsecurity/bbot/pull/3164)).
- `429 Too Many Requests` responses are now honored for rate limiting ([#3145](https://github.com/blacklanternsecurity/bbot/pull/3145)).
- HTTP timeout settings were consolidated into one place ([#3222](https://github.com/blacklanternsecurity/bbot/pull/3222)).
- SSL verification was split so BBOT verifies its own infrastructure calls by default while still not verifying untrusted target traffic ([#3186](https://github.com/blacklanternsecurity/bbot/pull/3186)).

#### DNS

- New DNS resolution engine, BlastDNS ([#3042](https://github.com/blacklanternsecurity/bbot/pull/3042)).
- Fixed the DNS brute-force canary check, which was silently non-functional ([#3005](https://github.com/blacklanternsecurity/bbot/pull/3005)).
- SPF records now yield the IPs and CIDRs they authorize ([#3144](https://github.com/blacklanternsecurity/bbot/pull/3144)).
- Better graph fidelity for shared infrastructure, and noisy PTR floods are collapsed / filtered by default ([#3141](https://github.com/blacklanternsecurity/bbot/pull/3141), [#3115](https://github.com/blacklanternsecurity/bbot/pull/3115), [#3039](https://github.com/blacklanternsecurity/bbot/pull/3039)).

#### Findings & Output

- Findings and Vulnerabilities are now a single event type carrying Severity and Confidence ([#2436](https://github.com/blacklanternsecurity/bbot/pull/2436), [#2740](https://github.com/blacklanternsecurity/bbot/pull/2740)).
- Human-readable stdout for every event type, improved URL display, and a finding-severity breakdown in the status line ([#3035](https://github.com/blacklanternsecurity/bbot/pull/3035), [#3023](https://github.com/blacklanternsecurity/bbot/pull/3023), [#3024](https://github.com/blacklanternsecurity/bbot/pull/3024)).
- Output modules are additive: enabling one keeps the defaults, with a new `exclude_output_modules` to opt out ([#3221](https://github.com/blacklanternsecurity/bbot/pull/3221)).
- Findings are de-duplicated in output, and `--no-color` is supported ([#3074](https://github.com/blacklanternsecurity/bbot/pull/3074)).

#### Modules

**New:**

- Output modules: MongoDB, Elastic, Kafka, RabbitMQ, ZeroMQ, and NATS.
- `legba` - credential brute-forcing across many services.
- `trajan` - scans GitHub, GitLab, Azure DevOps, Jenkins, and JFrog for misconfigurations.
- `virtualhost` - virtual-host fuzzing.
- `waf_bypass` - WAF-bypass detection.
- `shodan_enterprise` - Shodan Enterprise API integration.
- Hetzner object-storage bucket enumeration.

**Removed:** wappalyzer, smuggler, digitorus, sitedossier, passivetotal, wpscan.

**Notable improvements:**

- Lightfuzz overhaul: new SSRF and ESI submodules, "try POST as GET," a default WAF filter, and a large false-positive reduction across padding-oracle, deserialization, and SQLi detection ([#2967](https://github.com/blacklanternsecurity/bbot/pull/2967), [#2950](https://github.com/blacklanternsecurity/bbot/pull/2950), [#2784](https://github.com/blacklanternsecurity/bbot/pull/2784)).
- webbrute reworked around HttpCompare baselines; paramminer dedup and wordlist cleanup; gowitness reliability fixes; concurrent probing in aspnet_bin_exposure ([#3166](https://github.com/blacklanternsecurity/bbot/pull/3166), [#3067](https://github.com/blacklanternsecurity/bbot/pull/3067), [#3180](https://github.com/blacklanternsecurity/bbot/pull/3180)).
- shodan_idb now enriches CVE findings with severity and CVSS ([#3082](https://github.com/blacklanternsecurity/bbot/pull/3082)).
- Bundled scanners and signatures updated (nuclei, trufflehog, baddns, badsecrets).

#### Performance

- Broad memory and CPU pass: bounded (LRU) DNS caches, HTTP response bodies stripped after processing, repeated strings interned, and reduced event-loop saturation and allocation pressure - meaningfully lower memory footprint on large scans ([#2953](https://github.com/blacklanternsecurity/bbot/pull/2953), [#3085](https://github.com/blacklanternsecurity/bbot/pull/3085), [#3088](https://github.com/blacklanternsecurity/bbot/pull/3088), [#3003](https://github.com/blacklanternsecurity/bbot/pull/3003), [#3002](https://github.com/blacklanternsecurity/bbot/pull/3002)).

#### Security

- Hardened pickle handling in webbrute_shortnames plus additional input-validation patches ([#3200](https://github.com/blacklanternsecurity/bbot/pull/3200), [#3196](https://github.com/blacklanternsecurity/bbot/pull/3196), [#3201](https://github.com/blacklanternsecurity/bbot/pull/3201)).

#### Documentation

- New 2.x to 3.0 migration guide and a full documentation refresh ([#3128](https://github.com/blacklanternsecurity/bbot/pull/3128)).

### 2.8.6 - Jun 16, 2026
- 2.8.6 is expected to be the last 2.x release. Supported Python versions: 3.10-3.13.
- [https://github.com/blacklanternsecurity/bbot/pull/3199](https://github.com/blacklanternsecurity/bbot/pull/3199)

### 2.8.5 - Jun 16, 2026
- [https://github.com/blacklanternsecurity/bbot/pull/3185](https://github.com/blacklanternsecurity/bbot/pull/3185)

### 2.8.4 - Mar 17, 2026
- [https://github.com/blacklanternsecurity/bbot/pull/2971](https://github.com/blacklanternsecurity/bbot/pull/2971)

### 2.8.3 - Feb 26, 2026
- [https://github.com/blacklanternsecurity/bbot/pull/2922](https://github.com/blacklanternsecurity/bbot/pull/2922)

### 2.8.2 - Feb 12, 2026
- [https://github.com/blacklanternsecurity/bbot/pull/2899](https://github.com/blacklanternsecurity/bbot/pull/2899)

### 2.8.1 - Jan 30, 2026
- [https://github.com/blacklanternsecurity/bbot/pull/2888](https://github.com/blacklanternsecurity/bbot/pull/2888)

### 2.8.0 - Jan 20, 2026
- [https://github.com/blacklanternsecurity/bbot/pull/2760](https://github.com/blacklanternsecurity/bbot/pull/2760)

### 2.7.2 - Oct 25, 2025
- [https://github.com/blacklanternsecurity/bbot/pull/2717](https://github.com/blacklanternsecurity/bbot/pull/2717)

### 2.7.1 - Sep 16, 2025
- [https://github.com/blacklanternsecurity/bbot/pull/2700](https://github.com/blacklanternsecurity/bbot/pull/2700)

### 2.7.0 - Sep 11, 2025
- [https://github.com/blacklanternsecurity/bbot/pull/2610](https://github.com/blacklanternsecurity/bbot/pull/2610)

### 2.6.0 - Aug 12, 2025
- [https://github.com/blacklanternsecurity/bbot/pull/2492](https://github.com/blacklanternsecurity/bbot/pull/2492)

### 2.5.0 - June 3, 2025
- [https://github.com/blacklanternsecurity/bbot/pull/2435](https://github.com/blacklanternsecurity/bbot/pull/2435)

### 2.4.0 - Feb 27, 2025
- [https://github.com/blacklanternsecurity/bbot/pull/2266](https://github.com/blacklanternsecurity/bbot/pull/2266)

### 2.3.0 - Jan 24, 2025
- [https://github.com/blacklanternsecurity/bbot/pull/1986](https://github.com/blacklanternsecurity/bbot/pull/1986)

### 2.2.0 - Nov 18, 2024
- [https://github.com/blacklanternsecurity/bbot/pull/1919](https://github.com/blacklanternsecurity/bbot/pull/1919)

### 2.1.2 - Nov 1, 2024
- [https://github.com/blacklanternsecurity/bbot/pull/1909](https://github.com/blacklanternsecurity/bbot/pull/1909)

### 2.1.1 - Oct 31, 2024
- [https://github.com/blacklanternsecurity/bbot/pull/1885](https://github.com/blacklanternsecurity/bbot/pull/1885)

### 2.1.0 - Oct 18, 2024
- [https://github.com/blacklanternsecurity/bbot/pull/1724](https://github.com/blacklanternsecurity/bbot/pull/1724)

### 2.0.1 - Aug 29, 2024
- [https://github.com/blacklanternsecurity/bbot/pull/1650](https://github.com/blacklanternsecurity/bbot/pull/1650)

### 2.0.0 - Aug 9, 2024
- [https://github.com/blacklanternsecurity/bbot/pull/1424](https://github.com/blacklanternsecurity/bbot/pull/1424)
- [https://github.com/blacklanternsecurity/bbot/pull/1235](https://github.com/blacklanternsecurity/bbot/pull/1235)

### 1.1.8 - May 29, 2024
- [https://github.com/blacklanternsecurity/bbot/pull/1382](https://github.com/blacklanternsecurity/bbot/pull/1382)

### 1.1.7 - May 15, 2024
- [https://github.com/blacklanternsecurity/bbot/pull/1119](https://github.com/blacklanternsecurity/bbot/pull/1119)

### 1.1.6 - Feb 21, 2024
- [https://github.com/blacklanternsecurity/bbot/pull/1002](https://github.com/blacklanternsecurity/bbot/pull/1002)

### 1.1.5 - Jan 15, 2024
- [https://github.com/blacklanternsecurity/bbot/pull/996](https://github.com/blacklanternsecurity/bbot/pull/996)

### 1.1.4 - Jan 11, 2024
- [https://github.com/blacklanternsecurity/bbot/pull/837](https://github.com/blacklanternsecurity/bbot/pull/837)

### 1.1.3 - Nov 4, 2023
- [https://github.com/blacklanternsecurity/bbot/pull/823](https://github.com/blacklanternsecurity/bbot/pull/823)

### 1.1.2 - Nov 3, 2023
- [https://github.com/blacklanternsecurity/bbot/pull/777](https://github.com/blacklanternsecurity/bbot/pull/777)

### 1.1.1 - Oct 11, 2023
- [https://github.com/blacklanternsecurity/bbot/pull/668](https://github.com/blacklanternsecurity/bbot/pull/668)

### 1.1.0 - Aug 4, 2023
- [https://github.com/blacklanternsecurity/bbot/pull/598](https://github.com/blacklanternsecurity/bbot/pull/598)

### 1.0.5 - Mar 10, 2023
- [https://github.com/blacklanternsecurity/bbot/pull/352](https://github.com/blacklanternsecurity/bbot/pull/352)
