from pathlib import Path
from bbot.modules.internal.base import BaseInternalModule
from bbot.core.helpers.libmagic import get_magic_info, get_compression


class unarchive(BaseInternalModule):
    watched_events = ["FILESYSTEM"]
    produced_events = ["FILESYSTEM"]
    flags = ["passive", "safe"]
    meta = {
        "description": "Extract different types of files into folders on the filesystem",
        "created_date": "2024-12-08",
        "author": "@domwhewell-sage",
    }

    async def setup(self):
        self.ignore_compressions = ["application/java-archive", "application/vnd.android.package-archive"]
        self.compression_methods = {
            "zip": ["7z", "x", '-p""', "-aoa", "{filename}", "-o{extract_dir}/"],
            "bzip2": ["tar", "--overwrite", "-xvjf", "{filename}", "-C", "{extract_dir}/"],
            "xz": ["tar", "--overwrite", "-xvJf", "{filename}", "-C", "{extract_dir}/"],
            "7z": ["7z", "x", '-p""', "-aoa", "{filename}", "-o{extract_dir}/"],
            # "rar": ["7z", "x", '-p""', "-aoa", "{filename}", "-o{extract_dir}/"],
            # "lzma": ["7z", "x", '-p""', "-aoa", "{filename}", "-o{extract_dir}/"],
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
        success = await self.extract_file(path, output_dir)

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
            output_dir.rmdir()

    async def extract_file(self, path, output_dir):
        extension, mime_type, description, confidence = get_magic_info(path)
        compression_format = get_compression(mime_type)
        cmd_list = self.compression_methods.get(compression_format, [])
        if cmd_list:
            if not output_dir.exists():
                self.helpers.mkdir(output_dir)
            command = [s.format(filename=path, extract_dir=output_dir) for s in cmd_list]
            try:
                await self.run_process(command, check=True)
                for item in output_dir.iterdir():
                    if item.is_file():
                        await self.extract_file(item, output_dir / item.stem)
            except Exception as e:
                self.warning(f"Error extracting {path}. Error: {e}")
                return False
            return True
