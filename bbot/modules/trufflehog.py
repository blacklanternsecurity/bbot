import json
from bbot.modules.base import BaseModule


class trufflehog(BaseModule):
    watched_events = ["CODE_REPOSITORY", "FILESYSTEM"]
    produced_events = ["FINDING", "VULNERABILITY"]
    flags = ["passive", "safe", "code-enum"]
    meta = {
        "description": "TruffleHog is a tool for finding credentials",
        "created_date": "2024-03-12",
        "author": "@domwhewell-sage",
    }

    options = {
        "version": "3.81.9",
        "only_verified": True,
        "concurrency": 8,
        "deleted_forks": False,
    }
    options_desc = {
        "version": "trufflehog version",
        "only_verified": "Only report credentials that have been verified",
        "concurrency": "Number of concurrent workers",
        "deleted_forks": "Scan for deleted github forks. WARNING: This is SLOW. For a smaller repository, this process can take 20 minutes. For a larger repository, it could take hours.",
    }
    deps_ansible = [
        {
            "name": "Download trufflehog",
            "unarchive": {
                "src": "https://github.com/trufflesecurity/trufflehog/releases/download/v#{BBOT_MODULES_TRUFFLEHOG_VERSION}/trufflehog_#{BBOT_MODULES_TRUFFLEHOG_VERSION}_#{BBOT_OS}_#{BBOT_CPU_ARCH}.tar.gz",
                "include": "trufflehog",
                "dest": "#{BBOT_TOOLS}",
                "remote_src": True,
            },
        }
    ]

    scope_distance_modifier = 2

    async def setup(self):
        self.verified = self.config.get("only_verified", True)
        self.concurrency = int(self.config.get("concurrency", 8))

        self.deleted_forks = self.config.get("deleted_forks", False)
        self.github_token = ""
        if self.deleted_forks:
            self.warning(
                f"Deleted forks is enabled. Scanning for deleted forks is slooooooowwwww. For a smaller repository, this process can take 20 minutes. For a larger repository, it could take hours."
            )
            for module_name in ("github", "github_codesearch", "github_org", "git_clone"):
                module_config = self.scan.config.get("modules", {}).get(module_name, {})
                api_key = module_config.get("api_key", "")
                if api_key:
                    self.github_token = api_key
                    break

            # soft-fail if we don't have a github token as well
            if not self.github_token:
                self.deleted_forks = False
                return None, "A github api_key must be provided to the github modules for deleted forks to be scanned"
        return True

    async def filter_event(self, event):
        if event.type == "CODE_REPOSITORY":
            if self.deleted_forks:
                if "git" not in event.tags:
                    return False, "Module only accepts git CODE_REPOSITORY events"
                if "github" not in event.data["url"]:
                    return False, "Module only accepts github CODE_REPOSITORY events"
            else:
                return False, "Deleted forks is not enabled"
        return True

    async def handle_event(self, event):
        description = event.data.get("description", "")
        if event.type == "CODE_REPOSITORY":
            path = event.data["url"]
            if "git" in event.tags:
                module = "github-experimental"
        else:
            path = event.data["path"]
            if "git" in event.tags:
                module = "git"
            elif "docker" in event.tags:
                module = "docker"
            else:
                module = "filesystem"
        if event.type == "CODE_REPOSITORY":
            host = event.host
        else:
            host = str(event.parent.host)
        async for (
            decoder_name,
            detector_name,
            raw_result,
            rawv2_result,
            verified,
            source_metadata,
        ) in self.execute_trufflehog(module, path):
            if verified:
                data = {
                    "severity": "High",
                    "description": f"Verified Secret Found. Detector Type: [{detector_name}] Decoder Type: [{decoder_name}] Details: [{source_metadata}]",
                    "host": host,
                }
                if description:
                    data["description"] += f" Description: [{description}]"
                data["description"] += f" Raw result: [{raw_result}]"
                if rawv2_result:
                    data["description"] += f" RawV2 result: [{rawv2_result}]"
                await self.emit_event(
                    data,
                    "VULNERABILITY",
                    event,
                    context=f'{{module}} searched {event.type} using "{module}" method and found verified secret ({{event.type}}): {raw_result}',
                )
            else:
                data = {
                    "description": f"Potential Secret Found. Detector Type: [{detector_name}] Decoder Type: [{decoder_name}] Details: [{source_metadata}]",
                    "host": host,
                }
                if description:
                    data["description"] += f" Description: [{description}]"
                data["description"] += f" Raw result: [{raw_result}]"
                if rawv2_result:
                    data["description"] += f" RawV2 result: [{rawv2_result}]"
                await self.emit_event(
                    data,
                    "FINDING",
                    event,
                    context=f'{{module}} searched {event.type} using "{module}" method and found possible secret ({{event.type}}): {raw_result}',
                )

    async def execute_trufflehog(self, module, path):
        command = [
            "trufflehog",
            "--json",
            "--no-update",
        ]
        if self.verified:
            command.append("--only-verified")
        command.append("--concurrency=" + str(self.concurrency))
        if module == "git":
            command.append("git")
            command.append("file://" + path)
        elif module == "docker":
            command.append("docker")
            command.append("--image=file://" + path)
        elif module == "filesystem":
            command.append("filesystem")
            command.append(path)
        elif module == "github-experimental":
            command.append("github-experimental")
            command.append("--repo=" + path)
            command.append("--object-discovery")
            command.append("--delete-cached-data")
            command.append("--token=" + self.github_token)

        stats_file = self.helpers.tempfile_tail(callback=self.log_trufflehog_status)
        try:
            with open(stats_file, "w") as stats_fh:
                async for line in self.helpers.run_live(command, stderr=stats_fh):
                    try:
                        j = json.loads(line)
                    except json.decoder.JSONDecodeError:
                        self.debug(f"Failed to decode line: {line}")
                        continue

                    decoder_name = j.get("DecoderName", "")

                    detector_name = j.get("DetectorName", "")

                    raw_result = j.get("Raw", "")

                    rawv2_result = j.get("RawV2", "")

                    verified = j.get("Verified", False)

                    source_metadata = j.get("SourceMetadata", {})

                    yield (decoder_name, detector_name, raw_result, rawv2_result, verified, source_metadata)
        finally:
            stats_file.unlink()

    def log_trufflehog_status(self, line):
        try:
            line = json.loads(line)
        except Exception:
            self.info(str(line))
            return
        message = line.get("msg", "")
        ts = line.get("ts", "")
        status = f"Message: {message} | Timestamp: {ts}"
        self.info(status)
