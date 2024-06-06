import json
from bbot.modules.base import BaseModule


class trufflehog(BaseModule):
    watched_events = ["FILESYSTEM"]
    produced_events = ["FINDING", "VULNERABILITY"]
    flags = ["passive", "safe"]
    meta = {
        "description": "TruffleHog is a tool for finding credentials",
        "created_date": "2024-03-12",
        "author": "@domwhewell-sage",
    }

    options = {
        "version": "3.75.1",
        "only_verified": True,
        "concurrency": 8,
    }
    options_desc = {
        "version": "trufflehog version",
        "only_verified": "Only report credentials that have been verified",
        "concurrency": "Number of concurrent workers",
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
        return True

    async def handle_event(self, event):
        path = event.data["path"]
        description = event.data.get("description", "")
        if "git" in event.tags:
            module = "git"
        elif "docker" in event.tags:
            module = "docker"
        else:
            module = "filesystem"
        async for decoder_name, detector_name, raw_result, verified, source_metadata in self.execute_trufflehog(
            module, path
        ):
            if verified:
                data = {
                    "severity": "High",
                    "description": f"Verified Secret Found. Detector Type: [{detector_name}] Decoder Type: [{decoder_name}] Secret: [{raw_result}] Details: [{source_metadata}]",
                    "host": str(event.source.host),
                }
                if description:
                    data["description"] += f" Description: [{description}]"
                await self.emit_event(data, "VULNERABILITY", event)
            else:
                data = {
                    "description": f"Potential Secret Found. Detector Type: [{detector_name}] Decoder Type: [{decoder_name}] Secret: [{raw_result}] Details: [{source_metadata}]",
                    "host": str(event.source.host),
                }
                if description:
                    data["description"] += f" Description: [{description}]"
                await self.emit_event(data, "FINDING", event)

    async def execute_trufflehog(self, module, path):
        command = [
            "trufflehog",
            "--json",
        ]
        if self.verified:
            command.append("--only_verified")
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

                    verified = j.get("Verified", False)

                    source_metadata = j.get("SourceMetadata", {})

                    yield (decoder_name, detector_name, raw_result, verified, source_metadata)
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
