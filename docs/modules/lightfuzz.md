# Lightfuzz

*Lightfuzz is currently an experimental feature. There WILL be false positives (and, although we'll never know - false negatives), although the submodules are being actively worked on to reduce them. If you find false positives, please help us out by opening a GitHub issue with the details!*

## Philosophy

### What is Lightfuzz?

Lightfuzz is a lightweight web fuzzer built into BBOT. It is designed to find "low-hanging fruit" type vulnerabilities without much overhead and at massive scale.

### What is Lightfuzz NOT?

Lightfuzz is not, does not attempt to be, and will never be, a replacement for a full-blown web application scanner. You should not, for example, be running Lightfuzz as a replacement for Burp Suite scanning. Burp Suite scanner will always find more (even though we can find a few things it can't).

It will also not help you *exploit* what it finds. Its job is to point out likely issues and then pass them off to you. A great deal of the overhead with traditional scanners comes in the confirmation phase, or in testing exploitation payloads.

So for example, Lightfuzz may detect an XSS vulnerability for you. But it's NOT going to help you figure out which tag you need to use to get around a security filter, or give you any kind of a final payload. It's simply going to tell you that the contents of a given GET parameter are being reflected and that it was able to render an unmodified HTML tag. The rest is up to you.

### False Positives

Significant work has gone into minimizing false positives. However, due to the nature of how Lightfuzz works, they are a reality. Random hiccups in network connectivity can cause them in some cases, odd WAF behavior can account for others.

If you see a false positive that you feel is occurring too often or could easily be prevented, please open a GitHub issue and we will take a look!

### Deadly module

Lightfuzz currently has the `deadly` flag. This is applied to the most aggressive modules to enforce an additional check, requiring explicit acknowledgement of the risk using the `--allow-deadly` command line flag.

## Findings, Severity, and Confidence

All lightfuzz output is emitted as `FINDING` events. Each finding has two key attributes: **severity** and **confidence**.

### Severity

Severity represents how bad the issue is *if it's real*. Levels, from worst to least:

| Severity | Meaning |
|---|---|
| **CRITICAL** | Full system compromise likely (e.g., command injection, SSTI) |
| **HIGH** | Significant security impact (e.g., SQL injection, path traversal, unsafe deserialization) |
| **MEDIUM** | Moderate impact, often client-side (e.g., XSS, ESI) |
| **LOW** | Minor or limited-scope issue |
| **INFORMATIONAL** | Interesting observation, not directly exploitable (e.g., cryptographic parameter detected) |

### Confidence

Confidence represents how sure lightfuzz is that the finding is real, independent of severity. This is critical for triaging results — a HIGH-severity finding with LOW confidence needs manual verification, while a CRITICAL-severity finding with CONFIRMED confidence is almost certainly real.

| Confidence | Indicator | Meaning | Example |
|---|---|---|---|
| **CONFIRMED** | 🟣 | Out-of-band proof of exploitation | Blind command injection via DNS interaction (Interactsh) |
| **HIGH** | 🔴 | Deterministic detection that's hard to fake | SSTI math evaluation (`1337*1337=1787569`), padding oracle |
| **MODERATE** | 🟠 | Context-aware detection, but not definitive | SQL error strings after quote injection, XSS tag survival in reflection |
| **LOW** | 🟡 | Heuristic detection, requires manual verification | Blind SQLi timing (even with 3x confirmation), path traversal divergence, deserialization error changes |

When reviewing lightfuzz output, consider both dimensions together. A `CRITICAL` severity / `CONFIRMED` confidence finding (like OOB command injection) is something to act on immediately. A `HIGH` severity / `LOW` confidence finding (like blind SQLi timing) is worth investigating but may be a false positive.

## Submodules

Lightfuzz is divided into numerous "submodules". These would typically be run all together, but they can be configured to be run individually or in any desired configuration. This would be done with the aid of a `preset`, more on those in a moment.

### `cmdi` (Command Injection)
   - Finds output-based and blind out-of-band (via `Interactsh`) command injections
### `crypto` (Cryptography)
   - Identifies cryptographic parameters that have a tangible effect on the application
   - Can identify padding oracle vulnerabilities
   - Can identify hash length extension vulnerabilities
### `path` (Path Traversal)
   - Can find arbitrary file read / local-file include vulnerabilities, based on relative path traversal or with absolute paths
### `serial` (Deserialization)
   - Can identify the active deserialization of a variety of deserialization types across several platforms
### `sqli` (SQL Injection)
   - Error Based SQLi Detection
   - Blind time-delay SQLi Detection
### `ssti` (Server-side Template Injection)
   - Can find basic server-side template injection
### `xss` (Cross-site Scripting)
   - Can find a variety of XSS types, across several different contexts (between-tags, attribute, Javascript-based)
### `esi` (Edge Side Includes)
   - Detects Edge Side Include processing

## Submodule Details

### `cmdi` — Command Injection

Detects OS command injection via two techniques:

**Echo Canary Detection** (CRITICAL severity, MODERATE confidence): Injects command delimiters (`;`, `&&`, `||`, `&`, `|`) combined with an `echo` command containing a random numeric canary. If the canary appears in the response *without* the word "echo" (ruling out simple reflection), injection is indicated. A false-positive probe (`AAAA`) is sent first — if the canary appears with that delimiter, the test aborts since the application is just reflecting input.

**Blind OOB via Interactsh** (CRITICAL severity, CONFIRMED confidence): Injects `nslookup` commands pointed at unique Interactsh subdomains. If a DNS interaction is received, command execution is confirmed out-of-band. This is the highest-confidence detection lightfuzz can produce. Requires Interactsh to be enabled (it is by default).

### `sqli` — SQL Injection

Detects SQL injection via two techniques:

**Error-based Detection** (HIGH severity, MODERATE confidence): Injects a single quote (`'`) and compares the response against a list of known SQL error strings (e.g., "error in your SQL syntax", "Unterminated string literal"). Also performs a differential test: if a single quote changes the status code but two single quotes (`''`) produce a *different* status code, it suggests the quotes are being parsed as SQL syntax rather than just rejected.

**Blind Time-delay Detection** (HIGH severity, LOW confidence): Sends database-specific sleep payloads (PostgreSQL `pg_sleep`, MySQL `SLEEP`, Oracle `DBMS_LOCK.SLEEP`, MSSQL `WAITFOR DELAY`) with a 5-second delay. Measures response time against a baseline average of two normal requests. Requires 3 consecutive confirmations within an acceptable margin (1.5s) to report — even a single miss aborts the test for that payload. Despite the triple confirmation, timing-based detection is inherently noisy, hence the LOW confidence.

### `xss` — Cross-Site Scripting

Detects reflected XSS across multiple injection contexts. All XSS findings are MEDIUM severity, MODERATE confidence.

**Step 1 — Reflection Check**: Sends a random 8-character alphanumeric string. If it doesn't appear in the response, the parameter doesn't reflect and XSS testing is skipped entirely. Parameters from `paramminer_getparams` without an `http-reflection` tag are also skipped.

**Step 2 — Context Detection**: Determines where in the HTML the reflection occurs:

- **Between tags**: `<tag>REFLECTION</tag>`
- **In tag attribute**: `<tag attr="REFLECTION">`
- **In JavaScript**: `<script>var x = 'REFLECTION'</script>`

**Step 3 — Context-Specific Payloads**:

- *Between tags*: Tests whether HTML tags survive unmodified by injecting `<z>`, `<svg>`, and `<img>` tags. The `z` tag is arbitrary and less likely to be blocked by filters.
- *Tag attribute*: Tests quote escaping (`"z`), auto-quoting behavior, and `javascript:` scheme injection in form actions.
- *JavaScript*: First tries `</script><script>...</script>` tag breaking. If that fails, determines the quote context (single or double) and tests escape-the-escape-character techniques (`\'` → `\\'`).

Lightfuzz can often detect through WAFs since it does not attempt to construct full exploitation payloads.

### `path` — Path Traversal

Detects arbitrary file read / local file inclusion via two techniques:

**Relative Path Traversal** (HIGH severity, LOW confidence): The core technique is a single-dot vs. double-dot differential. If `./a/../VALUE` returns the same response as the original value (single dot is a no-op) but `../a/../VALUE` returns a *different* response (double dot changes the resolved path), it indicates real path manipulation. This is tested across 8 encoding variants:

- No encoding (with and without leading slash)
- URL encoding (with and without leading slash)
- Non-recursive stripping bypass (`....//`)
- Double URL encoding
- Start-of-path validation bypass (preserves original directory prefix)

Each variant requires **4 confirmations** across 5 iterations (one failure tolerated after the first success). WAF responses containing "The requested URL was rejected" are filtered out. Despite the multiple confirmations, this remains LOW confidence because response divergence can have non-traversal explanations.

**Absolute Path Detection** (HIGH severity, MODERATE confidence): Directly requests known file paths (`/etc/passwd`, `c:\windows\win.ini`) and checks for expected content strings (`daemon:x:`, `; for 16-bit app support`). Also tests null byte extension bypass (`%00.png`). Higher confidence because matching specific file content is much harder to explain away.

### `ssti` — Server-Side Template Injection

Detects template injection via arithmetic evaluation. All SSTI findings are HIGH severity, HIGH confidence.

Sends the expression `1337*1337` across multiple template syntaxes:

- `<%= 1337*1337 %>` (ERB/ASP, plus URL-encoded variant)
- `${1337*1337}` (EL/Freemarker, plus URL-encoded variant)
- `1,787{{z}},569` (Jinja2/Twig — if `{{z}}` is stripped, it becomes `1,787,569`)

If the response contains `1787569` (or `1,787,569`), the expression was evaluated server-side. This is a HIGH confidence detection because it's very unlikely for the exact product of two arbitrary numbers to appear in a response by coincidence.

### `crypto` — Cryptography Probe

Identifies cryptographic parameters and probes for cryptographic vulnerabilities. This submodule has several stages with varying confidence levels.

**Stage 1 — Cryptanalysis Gate**: Checks if the parameter value is likely encrypted by calculating Shannon entropy (threshold: 4.5) and whether its decoded length is a multiple of 8 (suggesting a block cipher). If entropy is below threshold, all further tests are skipped.

**Stage 2 — Response Divergence** (INFORMATIONAL severity, LOW confidence): Performs byte-level manipulations (truncation and single-byte mutation) and compares responses against both the baseline and an arbitrary garbage value. If the manipulated ciphertext produces a *different* response from both the original *and* garbage input, the parameter likely drives a real cryptographic operation.

**Stage 3 — Error String Detection** (INFORMATIONAL severity, LOW confidence): Scans manipulation responses for cryptographic error messages using YARA rules (e.g., "padding is invalid", "invalid mac", "OpenSSL Error"). Errors present in the baseline are filtered out to avoid false positives.

**Stage 4 — Padding Oracle** (HIGH severity, HIGH confidence): If a block cipher is suspected, performs a targeted padding oracle test. Constructs a crafted ciphertext with a null IV block and iterates through all 256 possible last-byte values. A true padding oracle produces a small number of differing responses (1 up to block_size, since multi-byte padding values like `\x02\x02` can also produce valid padding if the intermediate bytes happen to align). To avoid false positives from servers that reflect or reveal submitted/decrypted values, probe values are stripped from both responses before comparison, and small character-level differences (≤5 chars in equal-length responses) are tolerated. Handles the edge case where the baseline byte is the correct padding byte (1/255 chance) by retrying with a different baseline.

**Stage 5 — Hash Length Extension** (INFORMATIONAL severity, LOW confidence): If the parameter value matches a known hash length (MD5/SHA-1/SHA-256/SHA-384/SHA-512), checks whether modifying *other* parameters on the same request causes the hash parameter's response to change — suggesting those parameters are inputs to the hash, which could enable length extension attacks.

### `serial` — Unsafe Deserialization

Detects active deserialization of serialized objects. All deserialization findings are HIGH severity, LOW confidence.

Tests three encoding families (base64, hex, PHP raw) against control baselines crafted to *not* be valid serialized objects. For each family, sends known serialized payloads across multiple platforms:

- **Base64**: PHP, Java (Boolean, String, OptionalDataException), .NET, Ruby
- **Hex**: Java, Java OptionalDataException, .NET
- **PHP Raw**: PHP array

Two detection methods:

- **Error Resolution**: If the control baseline returns a non-200 status but the serialized payload returns 200 (excluding common error pages like "Internal Server Error"), the application likely recognized and processed the serialized data.
- **Differential Error Analysis**: If the response is a 500 (or a 200 with body changes), checks for deserialization-specific error strings like `java.io.optionaldataexception` or `cannot cast java.lang.string` that weren't present in the baseline.

Only runs on parameters whose existing values look potentially serialized (base64, hex, or PHP serialization prefixes), or on empty parameters.

### `esi` — Edge Side Includes

Detects ESI processing. ESI findings are MEDIUM severity, HIGH confidence.

Sends the payload `AA<!--esi-->BB<!--esx-->CC`. If the server processes ESI tags, the `<!--esi-->` comment is removed (it's a valid ESI directive) while `<!--esx-->` is left alone (not a valid directive). The expected detection string is `AABB<!--esx-->CC`. This is a clean differential test — the only explanation for selective comment removal is active ESI processing.

## Presets

Lightfuzz comes with pre-defined presets. Unless you really know BBOT inside and out, we recommend using one of them. This is because Lightfuzz needs to change several important BBOT settings to work correctly, including:

* Setting `url_querystring_remove` to False. By default, BBOT strips away querystrings, so in order to fuzz GET parameters, that default has to be disabled.
* Enabling complementary modules. Specifically, `hunt` and `reflected_parameters` can be useful companion modules when `WEB_PARAMETER` events are being emitted.

If you don't want to dive into those details, here are the built-in preset options.

### `-p lightfuzz-light`

Minimal preset that checks for only the most common findings (path traversal, SQLi, XSS). Enables a select few submodules and is safest for larger scans. POST requests are disabled.

### `-p lightfuzz-medium`

The default starting point. Enables all lightfuzz submodules and includes necessary config options, plus companion modules (`badsecrets`, `hunt`, `reflected_parameters`). **POST request fuzzing is disabled** — this is the most common concern for less aggressive scanning, especially on internal networks.

### `-p lightfuzz-heavy`

Everything in `lightfuzz-medium`, plus:

* **Param Miner** modules enabled for brute-force parameter discovery
* POST parameter fuzzing enabled
* Slightly increased spider settings

### `-p lightfuzz-superheavy`

Everything in `lightfuzz-heavy`, plus:

* Query string collapsing turned OFF — each unique parameter-value instance is fuzzed individually instead of being deduplicated
* Force common headers enabled — fuzz common header parameters (e.g., `X-Forwarded-For`) even if they weren't discovered
* Speculate GET parameters from JSON/XML response bodies

These settings add significant scan time and aren't typically desired for routine scanning.

### `-p lightfuzz-xss`

A focused preset for XSS hunting. Enables only the `xss` submodule with `paramminer_getparams` for parameter discovery. POST requests are disabled, and query string collapsing is off. This is an example of how to build a preset targeting specific submodules.

### Spider Preset

We *strongly* recommend running Lightfuzz with the spider enabled, as this will dramatically increase the number of parameters discovered. If you don't, you will see a warning reminding you.

Enable the spider by adding either the `spider` or `spider-intense` preset:

```
bbot -p lightfuzz-medium spider -t targets.txt --allow-deadly
```

## Usage

With presets in mind, usage is simple:

```
bbot -p lightfuzz-medium spider -t targets.txt --allow-deadly
```

All output from Lightfuzz will be `FINDING` events, each with a severity and confidence level. Focus your triage on confidence first — CONFIRMED and HIGH confidence findings are the most actionable, while LOW confidence findings should be treated as leads requiring manual verification.

### Selecting Specific Submodules

If you want a specific submodule, you can make your own preset adjusting the `modules.lightfuzz.enabled_submodules` setting, or do so via the command line:

Just XSS:
```
bbot -p lightfuzz-medium -t targets.txt -c modules.lightfuzz.enabled_submodules=[xss] --allow-deadly
```

XSS and SQLi:
```
bbot -p lightfuzz-medium -t targets.txt -c modules.lightfuzz.enabled_submodules=[xss,sqli] --allow-deadly
```

## HTTP Method Switching

Two options are available to test parameters across HTTP methods:

* **`try_post_as_get`**: For each `POSTPARAM` discovered, also fuzz it as a `GETPARAM`. This catches cases where a parameter accepted via POST is also accepted via GET, which may bypass server-side protections that only apply to one method.
* **`try_get_as_post`**: For each `GETPARAM` discovered, also fuzz it as a `POSTPARAM`. This catches cases where GET parameters are also accepted in POST bodies, potentially with different security controls.

These options are disabled by default. When enabled, findings from converted parameters will be annotated with their original method (e.g., "converted from POSTPARAM") in the finding description.

This is useful because web frameworks often accept parameters from multiple sources, but security filters (WAFs, input validation) may only apply to the originally intended method.

Enable via config:
```
bbot -p lightfuzz-medium -t targets.txt -c modules.lightfuzz.try_post_as_get=true modules.lightfuzz.try_get_as_post=true --allow-deadly
```
