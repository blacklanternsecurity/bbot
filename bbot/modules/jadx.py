from pathlib import Path
from subprocess import CalledProcessError
from bbot.modules.internal.base import BaseModule


class jadx(BaseModule):
    watched_events = ["FILESYSTEM"]
    produced_events = ["FILESYSTEM"]
    flags = ["passive", "safe", "code-enum"]
    meta = {
        "description": "Decompile APKs and XAPKs using JADX",
        "created_date": "2024-11-04",
        "author": "@domwhewell-sage",
    }
    options = {
        "threads": 4,
    }
    options_desc = {
        "threads": "Maximum jadx threads for extracting apk's, default: 4",
    }
    deps_common = ["java"]
    deps_ansible = [
        {
            "name": "Create jadx directory",
            "file": {"path": "#{BBOT_TOOLS}/jadx", "state": "directory", "mode": "0755"},
        },
        {
            "name": "Download jadx",
            "unarchive": {
                "src": "https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip",
                "include": ["lib/jadx-1.5.0-all.jar", "bin/jadx"],
                "dest": "#{BBOT_TOOLS}/jadx",
                "remote_src": True,
            },
        },
    ]

    allowed_file_types = ["java archive", "android application package"]

    async def setup(self):
        self.threads = self.config.get("threads", 4)
        return True

    async def filter_event(self, event):
        if "file" in event.tags:
            if event.data["magic_description"].lower() not in self.allowed_file_types:
                return False, f"Jadx is not able to decompile this file type: {event.data['magic_description']}"
        else:
            return False, "Event is not a file"
        return True

    async def handle_event(self, event):
        path = Path(event.data["path"])
        output_dir = path.parent / path.name.replace(".", "_")
        self.helpers.mkdir(output_dir)
        success = await self.decompile_apk(path, output_dir)

        # If jadx was able to decompile the java archive, emit an event
        if success:
            await self.emit_event(
                {"path": str(output_dir)},
                "FILESYSTEM",
                tags=["folder", "unarchived-folder"],
                parent=event,
                context=f'extracted "{path}" to: {output_dir}',
            )
        else:
            output_dir.rmdir()

    async def decompile_apk(self, path, output_dir):
        command = [
            f"{self.scan.helpers.tools_dir}/jadx/bin/jadx",
            "--threads-count",
            self.threads,
            "--output-dir",
            str(output_dir),
            str(path),
        ]
        try:
            output = await self.run_process(command, check=True)
        except CalledProcessError as e:
            self.warning(f"Error decompiling {path}. STDOUT: {e.stdout} STDERR: {repr(e.stderr)}")
            return False
        if not (output_dir / "resources").exists() and not (output_dir / "sources").exists():
            self.warning(f"JADX was unable to decompile {path}: (STDOUT: {output.stdout} STDERR: {output.stderr})")
            return False
        return True
