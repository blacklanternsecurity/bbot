from bbot.modules.base import BaseModule
from webcap.browser import Browser
from webcap import defaults
import tempfile
import os
import uuid
import csv
import shutil
import time
import re


class codeql(BaseModule):
    watched_events = ["URL"]
    produced_events = ["HTTP_RESPONSE_DOM"]
    flags = ["active"]
    meta = {
        "description": "experimental dom xss module using webcap",
        "created_date": "2025-03-05",
        "author": "@liquidsec",
    }
    deps_pip = ["webcap"]

    options = {"in_scope_only": False, "min_severity": "error", "suppress_duplicates": True}
    options_desc = {
        "in_scope_only": "Only process scripts residing on in-scope hosts",
        "min_severity": "Minimum severity level to report (error, warning, recommendation, note)",
        "suppress_duplicates": "Skip findings when identical files are analyzed on the same host (default: False)",
    }

    deps_ansible = [
        {"name": "Remove existing CodeQL directory", "file": {"path": "#{BBOT_TOOLS}/codeql", "state": "absent"}},
        {
            "name": "Create CodeQL directory",
            "file": {"path": "#{BBOT_TOOLS}/codeql", "state": "directory", "mode": "0755"},
            "register": "codeql_dir_created",
        },
        {
            "name": "Create databases directory",
            "file": {
                "path": "#{BBOT_TOOLS}/codeql/databases",
                "state": "directory",
                "mode": "0755",
            },
            "when": "codeql_dir_created is success",
        },
        {
            "name": "Create packages directory",
            "file": {
                "path": "#{BBOT_TOOLS}/codeql/packages",
                "state": "directory",
                "mode": "0755",
            },
            "when": "codeql_dir_created is success",
        },
        {
            "name": "Download CodeQL CLI",
            "unarchive": {
                "src": "https://github.com/github/codeql-cli-binaries/releases/download/v2.20.6/codeql-linux64.zip",
                "dest": "#{BBOT_TOOLS}/",
                "remote_src": True,
            },
            "register": "codeql_downloaded",
            "when": "codeql_dir_created is success",
        },
        {
            "name": "Make CodeQL executable",
            "file": {"path": "#{BBOT_TOOLS}/codeql/codeql", "mode": "u+x,g+x,o+x"},
            "when": "codeql_downloaded is success",
        },
        {
            "name": "Download JavaScript-all Query Pack to Custom Directory",
            "command": "#{BBOT_TOOLS}/codeql/codeql pack download codeql/javascript-all@2.5.1 --dir=#{BBOT_TOOLS}/codeql/packages --common-caches=#{BBOT_TOOLS}/codeql",
            "register": "query_pack_all_downloaded",
        },
        {
            "name": "Install JavaScript-all Query Pack from Custom Directory",
            "command": "#{BBOT_TOOLS}/codeql/codeql pack install #{BBOT_TOOLS}/codeql/packages/codeql/javascript-all/2.5.1 --no-strict-mode --common-caches=#{BBOT_TOOLS}/codeql",
            "when": "query_pack_all_downloaded is success",
            "register": "query_pack_all_installed",
        },
        {
            "name": "Download suite-helpers Query Pack to Custom Directory",
            "command": "#{BBOT_TOOLS}/codeql/codeql pack download codeql/suite-helpers@1.0.19 --dir=#{BBOT_TOOLS}/codeql/packages --common-caches=#{BBOT_TOOLS}/codeql",
            "when": "query_pack_all_installed is success",
            "register": "suite_helpers_downloaded",
        },
        {
            "name": "Install suite-helpers Query Pack from Custom Directory",
            "command": "#{BBOT_TOOLS}/codeql/codeql pack install #{BBOT_TOOLS}/codeql/packages/codeql/suite-helpers/1.0.19 --no-strict-mode --common-caches=#{BBOT_TOOLS}/codeql",
            "when": "suite_helpers_downloaded is success",
            "register": "suite_helpers_installed",
        },
        {
            "name": "Download typos Query Pack to Custom Directory",
            "command": "#{BBOT_TOOLS}/codeql/codeql pack download codeql/typos@1.0.19 --dir=#{BBOT_TOOLS}/codeql/packages --common-caches=#{BBOT_TOOLS}/codeql",
            "when": "suite_helpers_installed is success",
            "register": "typos_downloaded",
        },
        {
            "name": "Install typos Query Pack from Custom Directory",
            "command": "#{BBOT_TOOLS}/codeql/codeql pack install #{BBOT_TOOLS}/codeql/packages/codeql/typos/1.0.19 --no-strict-mode --common-caches=#{BBOT_TOOLS}/codeql",
            "when": "typos_downloaded is success",
            "register": "typos_installed",
        },
        {
            "name": "Download util Query Pack to Custom Directory",
            "command": "#{BBOT_TOOLS}/codeql/codeql pack download codeql/util@2.0.6 --dir=#{BBOT_TOOLS}/codeql/packages --common-caches=#{BBOT_TOOLS}/codeql",
            "when": "typos_installed is success",
            "register": "util_downloaded",
        },
        {
            "name": "Install util Query Pack from Custom Directory",
            "command": "#{BBOT_TOOLS}/codeql/codeql pack install #{BBOT_TOOLS}/codeql/packages/codeql/util/2.0.6 --no-strict-mode --common-caches=#{BBOT_TOOLS}/codeql",
            "when": "util_downloaded is success",
            "register": "util_installed",
        },
        {
            "name": "Download JavaScript-queries Query Pack to Custom Directory",
            "command": "#{BBOT_TOOLS}/codeql/codeql pack download codeql/javascript-queries@1.5.1 --dir=#{BBOT_TOOLS}/codeql/packages --common-caches=#{BBOT_TOOLS}/codeql",
            "when": "util_installed is success",
            "register": "query_pack_downloaded",
        },
        {
            "name": "Install JavaScript-queries Query Pack from Custom Directory",
            "command": "#{BBOT_TOOLS}/codeql/codeql pack install #{BBOT_TOOLS}/codeql/packages/codeql/javascript-queries/1.5.1 --no-strict-mode --common-caches=#{BBOT_TOOLS}/codeql",
            "when": "query_pack_downloaded is success",
        },
        {
            "name": "Create CodeQL custom queries directory",
            "file": {
                "path": "#{BBOT_TOOLS}/codeql/packages/codeql/javascript-queries/1.5.1/custom",
                "state": "directory",
                "mode": "0755",
            },
        },
        {
            "name": "Copy custom queries to CodeQL Custom Query Pack directory",
            "copy": {
                "src": "#{BBOT_WORDLISTS}/codeql_queries/",
                "dest": "#{BBOT_TOOLS}/codeql/packages/codeql/javascript-queries/1.5.1/custom/",
                "remote_src": False,
            },
        },
    ]

    in_scope_only = True
    _module_threads = 1

    yara_rules = r"""
    rule source_decode {
        meta:
            name = "Source Decoded with decodeURIComponent()"
            description = "URL-decoded user-controlled data from a source can facilitate XSS attacks"
            confidence = "possible"
        strings:
            $source_decode = /decodeURIComponent\s*\(\s*[^)]+(location\.(href|hash|pathname|search)|document\.(URL|documentURI|baseURI))[^)]*\)/ nocase
        condition:
            $source_decode
    }
    """

    async def setup(self):
        # Modify the cache to store findings
        self.processed_hashes = {}  # hash -> list of findings

        # Compile YARA rules during setup
        self.compiled_yara_rules = self.helpers.yara.compile(source=self.yara_rules)

        self.in_scope_only = self.config.get("in_scope_only", False)
        self.severity_levels = {"error": 4, "warning": 3, "recommendation": 2, "note": 1}
        self.min_severity = self.config.get("min_severity", "error").lower()
        if self.min_severity not in self.severity_levels:
            return (
                False,
                f"Invalid severity level '{self.min_severity}'. Valid options are: {', '.join(self.severity_levels.keys())}",
            )

        self.b = Browser(
            threads=defaults.threads,
            resolution=defaults.resolution,
            user_agent=defaults.user_agent,
            proxy=None,
            delay=3,
            full_page=False,
            dom=True,
            javascript=True,
            requests=False,
            responses=False,
            base64=False,
            ocr=False,
        )
        await self.b.start()

        # Build the query list during setup
        self.queries = [
            f"{self.helpers.tools_dir}/codeql/packages/codeql/javascript-queries/1.5.1/Security/CWE-020/MissingOriginCheck.ql",
            f"{self.helpers.tools_dir}/codeql/packages/codeql/javascript-queries/1.5.1/Security/CWE-079/ExceptionXss.ql",
            f"{self.helpers.tools_dir}/codeql/packages/codeql/javascript-queries/1.5.1/Security/CWE-346/CorsMisconfigurationForCredentials.ql",
            f"{self.helpers.tools_dir}/codeql/packages/codeql/javascript-queries/1.5.1/Security/CWE-079/XssThroughDom.ql",
            f"{self.helpers.tools_dir}/codeql/packages/codeql/javascript-queries/1.5.1/Security/CWE-079/StoredXss.ql",
            f"{self.helpers.tools_dir}/codeql/packages/codeql/javascript-queries/1.5.1/Security/CWE-079/UnsafeJQueryPlugin.ql",
            f"{self.helpers.tools_dir}/codeql/packages/codeql/javascript-queries/1.5.1/Security/CWE-079/UnsafeHtmlConstruction.ql",
            f"{self.helpers.tools_dir}/codeql/packages/codeql/javascript-queries/1.5.1/Security/CWE-079/Xss.ql",
            f"{self.helpers.tools_dir}/codeql/packages/codeql/javascript-queries/1.5.1/Security/CWE-079/ReflectedXss.ql",
            f"{self.helpers.tools_dir}/codeql/packages/codeql/javascript-queries/1.5.1/Security/CWE-601/ClientSideUrlRedirect.ql",
            f"{self.helpers.tools_dir}/codeql/packages/codeql/javascript-queries/1.5.1/Security/CWE-201/PostMessageStar.ql",
            f"{self.helpers.tools_dir}/codeql/packages/codeql/javascript-queries/1.5.1/Security/CWE-094/CodeInjection.ql",
            f"{self.helpers.tools_dir}/codeql/packages/codeql/javascript-queries/1.5.1/Security/CWE-094/ExpressionInjection.ql",
            f"{self.helpers.tools_dir}/codeql/packages/codeql/javascript-queries/1.5.1/AngularJS/InsecureUrlWhitelist.ql",
            f"{self.helpers.tools_dir}/codeql/packages/codeql/javascript-queries/1.5.1/AngularJS/DisablingSce.ql",
            f"{self.helpers.tools_dir}/codeql/packages/codeql/javascript-queries/1.5.1/Security/CWE-915/PrototypePollutingAssignment.ql",
            f"{self.helpers.tools_dir}/codeql/packages/codeql/javascript-queries/1.5.1/Security/CWE-915/PrototypePollutingFunction.ql",
            f"{self.helpers.tools_dir}/codeql/packages/codeql/javascript-queries/1.5.1/Security/CWE-915/PrototypePollutingMergeCall.ql",
            f"{self.helpers.tools_dir}/codeql/packages/codeql/javascript-queries/1.5.1/custom/dom-xss-jquery-contains.ql",
            f"{self.helpers.tools_dir}/codeql/packages/codeql/javascript-queries/1.5.1/custom/xmlhttprequest-to-eval.ql",
        ]

        # Clean up any stale database files older than 3 days
        database_dir = os.path.join(self.scan.helpers.tools_dir, "codeql", "databases")
        if os.path.exists(database_dir):
            current_time = time.time()
            three_days_in_seconds = 3 * 24 * 60 * 60

            for item in os.listdir(database_dir):
                item_path = os.path.join(database_dir, item)
                # Get the last modification time of the file/directory
                try:
                    mtime = os.path.getmtime(item_path)
                    if (current_time - mtime) > three_days_in_seconds:
                        if os.path.isfile(item_path):
                            os.unlink(item_path)
                        elif os.path.isdir(item_path):
                            shutil.rmtree(item_path)
                        self.debug(f"Cleaned up stale CodeQL database: {item_path}")
                except Exception as e:
                    self.debug(f"Error checking/removing {item_path}: {e}")

        return True

    async def execute_codeql_create_db(self, source_root, database_path):
        command = [
            f"{self.scan.helpers.tools_dir}/codeql/codeql",
            "database",
            "create",
            database_path,
            "--language=javascript",
            f"--common-caches={self.scan.helpers.tools_dir}/codeql/",
            f"--source-root={source_root}",
        ]
        self.verbose("Executing CodeQL command to create db")
        async for line in self.run_process_live(command):
            pass

    async def execute_codeql_analyze_db(self, database_path):
        # Create a temporary file for the output
        with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as temp_file:
            output_path = temp_file.name

        command = [
            f"{self.scan.helpers.tools_dir}/codeql/codeql",
            "database",
            "analyze",
            database_path,
            "--format=csv",
            f"--common-caches={self.scan.helpers.tools_dir}/codeql",
            f"--additional-packs={self.scan.helpers.tools_dir}/codeql/packages",
            *self.queries,
            f"--output={output_path}",
        ]

        self.verbose("Executing CodeQL command to analyze db")

        # Run the command and capture the output
        async for line in self.run_process_live(command):
            self.debug(f"CodeQL analysis output: {line}")

        # Read and parse the CSV results
        results = []
        with open(output_path, "r") as file:
            csv_reader = csv.reader(file)
            for row in csv_reader:
                if len(row) >= 9:  # Ensure we have all expected fields
                    results.append(
                        {
                            "title": row[0],
                            "full_description": row[1],
                            "severity": row[2],
                            "message": row[3],
                            "file": row[4],
                            "start_line": int(row[5]) if row[5].isdigit() else "N/A",
                            "start_column": int(row[6]) if row[6].isdigit() else "N/A",
                            "end_line": int(row[7]) if row[7].isdigit() else "N/A",
                            "end_column": int(row[8]) if row[8].isdigit() else "N/A",
                        }
                    )

        # Clean up the temporary file
        os.remove(output_path)

        return results

    async def store_and_emit_finding(self, finding_data, event, files_hash):
        """Store finding in cache and emit event."""
        # Store everything except URL and host
        cache_data = finding_data.copy()
        cache_data["data"] = finding_data["data"].copy()
        cache_data["data"].pop("url", None)  # Remove URL from cached data
        cache_data["data"].pop("host", None)  # Remove host from cached data
        self.processed_hashes[files_hash].append(cache_data)
        self.verbose(f"Storing finding in cache for hash: {files_hash}, url: {finding_data['data'].get('url', 'N/A')}")

        await self.emit_event(finding_data["data"], "FINDING", event, context=finding_data["context"])

    async def emit_cached_findings(self, files_hash, event):
        """Emit all findings from cache for a given hash."""
        for cached_finding in self.processed_hashes[files_hash]:
            # Create new finding data with current URL and host
            finding_data = cached_finding.copy()
            finding_data["data"] = cached_finding["data"].copy()
            finding_data["data"]["url"] = str(event.data)  # Add current URL
            finding_data["data"]["host"] = str(event.host)  # Add current host

            await self.emit_event(finding_data["data"], "FINDING", event, context=finding_data["context"])

    def extract_code_snippet(self, file_path, start_line, start_col, end_line, end_col):
        """Extract a code snippet from a file given line and column numbers."""
        try:
            with open(file_path, "r") as f:
                lines = f.readlines()
                code_snippet = None

                if isinstance(start_line, int):
                    start_line -= 1  # Adjust for zero-based index
                    full_line = lines[start_line].strip().encode("ascii", "replace").decode()

                    if len(full_line) <= 150:
                        code_snippet = full_line
                    elif all(isinstance(x, int) for x in [start_col, end_col]):
                        code_snippet = full_line[start_col - 1 : end_col]
                    else:
                        code_snippet = full_line[:147] + "..."

                return code_snippet
        except Exception as e:
            self.debug(f"Error extracting code snippet from {file_path}: {e}")
            return "N/A"

    async def handle_event(self, event):
        with tempfile.TemporaryDirectory() as temp_dir:
            files_to_process = {}  # hash -> (file_path, script_url, original_url)

            async for url, webscreenshot in self.b.screenshot_urls([event.data]):
                scripts = webscreenshot.scripts

                for i, js in enumerate(scripts):
                    script_url = js.json.get("url", url)

                    # Skip out-of-scope scripts if in_scope_only is True
                    if self.in_scope_only:
                        try:
                            parsed_url = self.helpers.urlparse(script_url)
                            script_domain = parsed_url.netloc
                            if not self.scan.in_scope(script_domain):
                                self.debug(f"Skipping out-of-scope script: {script_url}")
                                continue
                        except Exception as e:
                            self.debug(f"Error parsing script URL {script_url}: {e}")
                            continue

                    loaded_js = js.json["script"]
                    file_path = os.path.join(temp_dir, f"script_{i}.js")

                    # Write file contents
                    with open(file_path, "w") as js_file:
                        js_file.write(loaded_js)

                    # Calculate hash
                    file_hash = await self.get_file_hash(file_path)

                    if file_hash in self.processed_hashes:
                        if self.config.get("suppress_duplicates", False):
                            self.debug(f"Suppressing duplicate findings for hash: {file_hash} on host {event.host}")
                        else:
                            self.verbose(f"Cache hit - reemitting findings for hash: {file_hash}")
                            await self.emit_cached_findings(file_hash, event)
                        # Delete the file if it's already processed
                        os.remove(file_path)
                    else:
                        self.debug(f"No hash match for [{script_url}]: {file_hash}")
                        self.processed_hashes[file_hash] = []
                        files_to_process[file_hash] = (file_path, script_url, str(event.data))

            # Check if there are files to process
            if files_to_process:
                self.debug(f"Processing {len(files_to_process)} files")

                # Generate a consistent database path
                database_path = os.path.join(self.helpers.tools_dir, "codeql", "databases", str(uuid.uuid4()))
                os.makedirs(database_path, exist_ok=True)

                findings_map = await self.codeql_process_files(temp_dir, files_to_process, database_path)
                await self.process_findings(files_to_process, findings_map, event)

                # Clean up the specific database directory used
                if os.path.exists(database_path):
                    shutil.rmtree(database_path)
                    self.debug(f"Cleaned up database directory: {database_path}")

    async def process_findings(self, files_to_process, findings_map, event):
        """Process and emit findings for a batch of files."""
        for file_hash, findings in findings_map.items():
            _, script_url, original_url = files_to_process[file_hash]
            for finding in findings:
                # Update finding with correct URLs
                finding["data"]["url"] = original_url
                finding["data"]["script_url"] = script_url
                await self.store_and_emit_finding(finding, event, file_hash)

    async def process_message(self, message, file_path):
        """Process the message to replace double-bracketed sections with detailed information."""

        def replace_brackets(match):
            details = match.group(1)
            parts = details.split("|")
            description = parts[0].strip().strip('"')
            location = parts[1].replace("relative:///", "").strip().strip('"').split(":")
            start_line, start_col, end_line, end_col = map(int, location[1:])
            code_snippet = self.extract_code_snippet(file_path, start_line, start_col, end_line, end_col)
            if len(code_snippet) > 150:
                code_snippet = code_snippet[:197] + "..."
            return f"{description}: [{code_snippet}]"

        # Use regex to find and replace double-bracketed sections
        pattern = r"\[\[(.*?)\]\]"
        processed_message = re.sub(pattern, replace_brackets, message)
        return processed_message.replace("\n", " ")

    async def codeql_process_files(self, temp_dir, files_to_process, database_path):
        """Process multiple files in a single CodeQL database."""
        findings_map = {hash_: [] for hash_ in files_to_process.keys()}

        # First run YARA checks for all files
        for file_hash, (file_path, script_url, _) in files_to_process.items():
            try:
                with open(file_path, "r") as f:
                    content = f.read()
                    results = await self.helpers.yara.match(self.compiled_yara_rules, content, full_result=True)
                    for result in results:
                        yara_description = result["meta"].get("description", "")
                        confidence = result["meta"].get("confidence", "")
                        rule_name = result["meta"].get("name", result["rule"])

                        description = f"{rule_name}: {yara_description}."
                        if confidence:
                            description += f" Confidence: [{confidence}]"

                        matched_text = result["matched_string"]
                        if len(matched_text) > 150:
                            matched_text = matched_text[:147] + "..."
                        description += f" Matched Text: [{matched_text}]"
                        description += f" Location: [{script_url}]"

                        finding_data = {
                            "data": {
                                "description": f"POSSIBLE Client-side Vulnerability (YARA Match). {description})",
                                "script_url": script_url,
                            },
                            "context": f"{{module}} module found a YARA match for rule '{rule_name}' in {script_url}",
                        }
                        findings_map[file_hash].append(finding_data)
            except Exception as e:
                self.debug(f"Error processing YARA for {file_path}: {e}")

        # Create and analyze CodeQL database
        await self.execute_codeql_create_db(temp_dir, database_path)
        results = await self.execute_codeql_analyze_db(database_path)

        # Process CodeQL results
        for result in results:
            file_path = os.path.join(temp_dir, result["file"].lstrip("/"))

            # Map result back to original file
            file_hash = None
            script_url = None
            for h, (fp, url, _) in files_to_process.items():
                if os.path.samefile(fp, file_path):
                    file_hash = h
                    script_url = url
                    break

            if not file_hash:
                self.debug(f"Could not map result back to original file: {file_path}")
                continue

            # Extract code snippet and process finding
            try:
                start_line = result.get("start_line")
                code_snippet = self.extract_code_snippet(
                    file_path, start_line, result.get("start_column"), result.get("end_line"), result.get("end_column")
                )

                if not self.severity_threshold(result["severity"]):
                    continue

                location_details = f"Line: {start_line + 1}"
                if isinstance(result.get("start_column"), int) and isinstance(result.get("end_column"), int):
                    location_details += f" Cols: {result['start_column']}-{result['end_column']}"

                details_string = (
                    f"{result['title']}. Description: {result['full_description']} "
                    f"Severity: [{result['severity']}] Location: [{script_url} ({location_details})] "
                    f"Code Snippet: [{code_snippet}]"
                )
                if result.get("message"):
                    processed_message = await self.process_message(result["message"], file_path)
                    details_string += f" Details: {processed_message}"

                finding_data = {
                    "data": {
                        "description": f"POSSIBLE Client-side Vulnerability: {details_string}",
                        "script_url": script_url,
                    },
                    "context": f"{{module}} module found POSSIBLE Client-side Vulnerability: {details_string}",
                }
                findings_map[file_hash].append(finding_data)

            except Exception as e:
                self.debug(f"Error processing finding for {file_path}: {e}")

        return findings_map

    def severity_threshold(self, severity):
        severity = severity.lower()
        min_level = self.severity_levels.get(self.min_severity, 4)  # Default to error if invalid
        current_level = self.severity_levels.get(severity, 0)  # Default to 0 if unknown severity
        return current_level >= min_level

    async def get_file_hash(self, file_path):
        """Calculate a fast hash of a single file using built-in hash function."""
        hash_value = 0
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(8192):
                    hash_value = ((hash_value * 31) + hash(chunk)) & 0xFFFFFFFF
        except Exception as e:
            self.debug(f"Error hashing file {file_path}: {e}")

        return str(hash_value)
