from pathlib import Path
from contextlib import suppress
from bbot.modules.internal.base import BaseInternalModule
from bbot.core.helpers.libmagic import get_magic_info, get_compression


class unarchive(BaseInternalModule):
    watched_events = ["FILESYSTEM"]
    produced_events = ["FILESYSTEM"]
    flags = ["safe", "passive"]
    meta = {
        "description": "Extract different types of files into folders on the filesystem",
        "created_date": "2024-12-08",
        "author": "@domwhewell-sage",
    }

    _max_extracted_size = 1_000_000_000  # 1 GB

    async def setup(self):
        self.ignore_compressions = ["application/java-archive", "application/vnd.android.package-archive"]
        self.compression_methods = {
            "zip": ["7z", "x", "-aoa", "{filename}", "-o{extract_dir}/"],
            "bzip2": ["tar", "--overwrite", "-xvjf", "{filename}", "-C", "{extract_dir}/"],
            "xz": ["tar", "--overwrite", "-xvJf", "{filename}", "-C", "{extract_dir}/"],
            "7z": ["7z", "x", "-aoa", "{filename}", "-o{extract_dir}/"],
            # "rar": ["7z", "x", "-aoa", "{filename}", "-o{extract_dir}/"],
            # "lzma": ["7z", "x", "-aoa", "{filename}", "-o{extract_dir}/"],
            "tar": ["tar", "--overwrite", "-xvf", "{filename}", "-C", "{extract_dir}/"],
            "gzip": ["tar", "--overwrite", "-xvzf", "{filename}", "-C", "{extract_dir}/"],
        }
        return True

    async def filter_event(self, event):
        if "file" in event.tags:
            magic_mime_type = event.data.get("magic_mime_type", "")
            if magic_mime_type in self.ignore_compressions:
                return False, f"Ignoring file type: {magic_mime_type}, {event.data['path']}"
            if "compression" in event.data:
                if not event.data["compression"] in self.compression_methods:
                    return (
                        False,
                        f"Extract unable to handle file type: {event.data['compression']}, {event.data['path']}",
                    )
            else:
                return False, f"Event is not a compressed file: {event.data['path']}"
        else:
            return False, "Event is not a file"
        return True

    async def handle_event(self, event):
        path = Path(event.data["path"])
        output_dir = path.parent / path.name.replace(".", "_")

        # Use the appropriate extraction method based on the file type
        self.info(f"Extracting {path} to {output_dir}")
        budget = [self._max_extracted_size]
        success = await self.extract_file(path, output_dir, budget)

        # If the extraction was successful, emit the event
        if success:
            await self.emit_event(
                {"path": str(output_dir)},
                "FILESYSTEM",
                tags=["folder", "unarchived-folder"],
                parent=event,
                context=f'extracted "{path}" to: {output_dir}',
            )
        else:
            with suppress(OSError):
                output_dir.rmdir()

    async def extract_file(self, path, output_dir, budget=None):
        if budget is None:
            budget = [self._max_extracted_size]
        extension, mime_type, description, confidence = get_magic_info(path)
        compression_format = get_compression(mime_type)
        cmd_list = self.compression_methods.get(compression_format, [])
        if cmd_list:
            # output dir must not already exist
            try:
                output_dir.mkdir(exist_ok=False)
            except FileExistsError:
                self.warning(f"Destination directory {output_dir} already exists, aborting unarchive for {path}")
                return False
            if not await self._check_archive_safe(path, compression_format, budget):
                return False
            command = [s.format(filename=path, extract_dir=output_dir) for s in cmd_list]
            try:
                await self.run_process(command, check=True)
                extracted_size = sum(f.stat().st_size for f in output_dir.rglob("*") if f.is_file())
                budget[0] -= extracted_size
                if budget[0] < 0:
                    self.helpers.rm_rf(output_dir)
                    self.warning(f"Cumulative extracted size exceeds limit, removing {output_dir}")
                    return False
                for item in output_dir.iterdir():
                    if item.is_file():
                        await self.extract_file(item, output_dir / item.stem, budget)
            except Exception as e:
                self.warning(f"Error extracting {path}. Error: {e}")
                return False
            return True

    async def _check_archive_safe(self, path, compression_format, budget=None):
        if compression_format in ("zip", "7z"):
            result = await self.run_process(["7z", "l", "-slt", str(path)])
            output_lines = result.stdout.splitlines()
            entries = [line.split("= ", 1)[1] for line in output_lines if line.startswith("Path = ")]
            entries = entries[1:]
            # reject symlink/hardlink entries
            for line in output_lines:
                if line.startswith("Link = "):
                    self.warning(f"Archive {path} contains symlink or link entry")
                    return False
                if line.startswith("Attributes = "):
                    attr = line.split("= ", 1)[1].strip()
                    # p7zip may prefix a DOS attribute block before the unix mode string,
                    # e.g. "_ lrwxrwxrwx" for a symlink or "D drwxr-xr-x" for a directory.
                    # The unix type flag is the first character of the mode field, so check
                    # both the raw value and the trailing mode field for "l"/"h".
                    mode = attr.split()[-1] if attr.split() else ""
                    if attr[:1] in ("l", "h") or mode[:1] in ("l", "h"):
                        self.warning(f"Archive {path} contains symlink or link entry")
                        return False
            # check declared uncompressed size before extracting
            declared_size = 0
            for line in output_lines:
                if line.startswith("Size = "):
                    with suppress(ValueError):
                        declared_size += int(line.split("= ", 1)[1].strip())
            if budget is not None and declared_size > budget[0]:
                self.warning(
                    f"Archive {path} declared size {declared_size:,} bytes exceeds remaining budget "
                    f"({budget[0]:,} bytes), skipping"
                )
                return False
        else:
            result = await self.run_process(["tar", "-tf", str(path)])
            entries = result.stdout.splitlines()
            # reject symlink/hardlink entries via verbose listing
            verbose = await self.run_process(["tar", "-tvf", str(path)])
            declared_size = 0
            for line in verbose.stdout.splitlines():
                if line and line[0] in ("l", "h"):
                    self.warning(f"Archive {path} contains symlink or hardlink entry")
                    return False
                parts = line.split()
                if len(parts) >= 3:
                    with suppress(ValueError):
                        declared_size += int(parts[2])
            if budget is not None and declared_size > budget[0]:
                self.warning(
                    f"Archive {path} declared size {declared_size:,} bytes exceeds remaining budget "
                    f"({budget[0]:,} bytes), skipping"
                )
                return False
        for entry in entries:
            entry = entry.strip()
            if not entry:
                continue
            parts = Path(entry).parts
            if ".." in parts or entry.startswith("/"):
                self.warning(f"Archive {path} contains path traversal entry: {entry}")
                return False
        return True
