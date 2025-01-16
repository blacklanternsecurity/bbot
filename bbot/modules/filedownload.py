import json
from pathlib import Path

from bbot.modules.base import BaseModule


class filedownload(BaseModule):
    """
    Watch for common filetypes and download them.

    Capable of identifying interesting files even if the extension is not in the URL.
    E.g. if a PDF is being served at https://evilcorp.com/mypdf, it will still be downloaded and given the proper extension.
    """

    watched_events = ["URL_UNVERIFIED", "HTTP_RESPONSE"]
    produced_events = ["FILESYSTEM"]
    flags = ["active", "safe", "web-basic"]
    meta = {
        "description": "Download common filetypes such as PDF, DOCX, PPTX, etc.",
        "created_date": "2023-10-11",
        "author": "@TheTechromancer",
    }
    options = {
        "extensions": [
            "bak",  #  Backup File
            "bash",  #  Bash Script or Configuration
            "bashrc",  #  Bash Script or Configuration
            "cfg",  #  Configuration File
            "conf",  #  Configuration File
            "crt",  #  Certificate File
            "csv",  #  Comma Separated Values File
            "db",  #  SQLite Database File
            "dll",  #  Windows Dynamic Link Library
            "doc",  #  Microsoft Word Document (Old Format)
            "docx",  #  Microsoft Word Document
            "exe",  #  Windows PE executable
            "ica",  #  Citrix Independent Computing Architecture File
            "indd",  #  Adobe InDesign Document
            "ini",  #  Initialization File
            "jar",  #  Java Archive
            "json",  #  JSON File
            "key",  #  Private Key File
            "log",  #  Log File
            "markdown",  #  Markdown File
            "md",  #  Markdown File
            "msi",  # Windows setup file
            "odg",  #  OpenDocument Graphics (LibreOffice, OpenOffice)
            "odp",  #  OpenDocument Presentation (LibreOffice, OpenOffice)
            "ods",  #  OpenDocument Spreadsheet (LibreOffice, OpenOffice)
            "odt",  #  OpenDocument Text (LibreOffice, OpenOffice)
            "pdf",  #  Adobe Portable Document Format
            "pem",  #  Privacy Enhanced Mail (SSL certificate)
            "pps",  #  Microsoft PowerPoint Slideshow (Old Format)
            "ppsx",  #  Microsoft PowerPoint Slideshow
            "ppt",  #  Microsoft PowerPoint Presentation (Old Format)
            "pptx",  #  Microsoft PowerPoint Presentation
            "ps1",  #  PowerShell Script
            "pub",  #  Public Key File
            "raw",  #  Raw Image File Format
            "rdp",  #  Remote Desktop Protocol File
            "rsa",  #  RSA Private Key File
            "sh",  #  Shell Script
            "sql",  #  SQL Database Dump
            "sqlite",  #  SQLite Database File
            "swp",  #  Swap File (temporary file, often Vim)
            "sxw",  #  OpenOffice.org Writer document
            "tar.gz",  # Gzip-Compressed Tar Archive
            "tgz",  #  Gzip-Compressed Tar Archive
            "tar",  #  Tar Archive
            "txt",  #  Plain Text Document
            "vbs",  #  Visual Basic Script
            "war",  #  Java Web Archive
            "wpd",  #  WordPerfect Document
            "xls",  #  Microsoft Excel Spreadsheet (Old Format)
            "xlsx",  #  Microsoft Excel Spreadsheet
            "xml",  #  eXtensible Markup Language File
            "yaml",  #  YAML Ain't Markup Language
            "yml",  #  YAML Ain't Markup Language
            "zip",  #  Zip Archive
            "lzma",  #  LZMA Compressed File
            "rar",  #  RAR Compressed File
            "7z",  #  7-Zip Compressed File
            "xz",  #  XZ Compressed File
            "bz2",  #  Bzip2 Compressed File
        ],
        "max_filesize": "10MB",
        "base_64_encoded_file": "false",
    }
    options_desc = {
        "extensions": "File extensions to download",
        "max_filesize": "Cancel download if filesize is greater than this size",
        "base_64_encoded_file": "Stream the bytes of a file and encode them in base 64 for event data.",
    }

    scope_distance_modifier = 3

    async def setup(self):
        self.extensions = list({e.lower().strip(".") for e in self.config.get("extensions", [])})
        self.max_filesize = self.config.get("max_filesize", "10MB")
        self.download_dir = self.scan.home / "filedownload"
        self.helpers.mkdir(self.download_dir)
        self.urls_downloaded = set()
        self.files_downloaded = 0
        self.mime_db_file = await self.helpers.wordlist(
            "https://raw.githubusercontent.com/jshttp/mime-db/master/db.json"
        )
        self.mime_db = {}
        with open(self.mime_db_file) as f:
            mime_db = json.load(f)
            for content_type, attrs in mime_db.items():
                if "extensions" in attrs and attrs["extensions"]:
                    self.mime_db[content_type] = attrs["extensions"][0].lower()
        return True

    async def filter_event(self, event):
        # accept file download requests from other modules
        if "filedownload" in event.tags:
            return True
        else:
            if event.scope_distance > 0:
                return False, f"{event} not within scope distance"
            elif self.hash_event(event) in self.urls_downloaded:
                return False, f"Already processed {event}"
        return True

    def hash_event(self, event):
        if event.type == "HTTP_RESPONSE":
            return hash(event.data["url"])
        return hash(event.data)

    async def handle_event(self, event):
        if event.type == "URL_UNVERIFIED":
            url_lower = event.data.lower()
            extension_matches = any(url_lower.endswith(f".{e}") for e in self.extensions)
            filedownload_requested = "filedownload" in event.tags
            if extension_matches or filedownload_requested:
                await self.download_file(event.data, source_event=event)
        elif event.type == "HTTP_RESPONSE":
            headers = event.data.get("header", {})
            content_type = headers.get("content_type", "")
            if content_type:
                url = event.data["url"]
                await self.download_file(url, content_type=content_type, source_event=event)

    async def download_file(self, url, content_type=None, source_event=None):
        orig_filename, file_destination, base_url = self.make_filename(url, content_type=content_type)
        if orig_filename is None:
            return
        result = await self.helpers.download(url, warn=False, filename=file_destination, max_size=self.max_filesize)
        if result:
            self.info(f'Found "{orig_filename}" at "{base_url}", downloaded to {file_destination}')
            self.files_downloaded += 1
            if source_event:
                file_event = self.make_event(
                    {"path": str(file_destination)}, "FILESYSTEM", tags=["filedownload", "file"], parent=source_event
                )
                if file_event is not None:
                    await self.emit_event(file_event)
        self.urls_downloaded.add(hash(url))

    def make_filename(self, url, content_type=None):
        # first, try to determine original filename
        parsed_url = self.helpers.urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        url_path = parsed_url.path.strip("/")
        # try to get extension from URL path
        extension = Path(url_path).suffix.strip(".").lower()
        if extension:
            url_stem = url.rsplit(".", 1)[0]
        else:
            url_stem = str(url)
        filename = f"{self.helpers.make_date()}_{self.helpers.tagify(url_stem)}"
        if not url_path:
            url_path = "unknown"
            filename = f"{filename}-{url_path}"
        # if that fails, try to get it from content type
        if not extension:
            if content_type and content_type in self.mime_db:
                extension = self.mime_db[content_type]

        if (not extension) or (extension not in self.extensions):
            self.debug(f'Extension "{extension}" at url "{url}" not in list of watched extensions.')
            return None, None, None

        orig_filename = Path(url_path).stem
        if extension:
            filename = f"{filename}.{extension}"
            orig_filename = f"{orig_filename}.{extension}"
        file_destination = self.download_dir / filename
        file_destination = self.helpers.truncate_filename(file_destination)
        return orig_filename, file_destination, base_url

    async def report(self):
        if self.files_downloaded > 0:
            self.success(f"Downloaded {self.files_downloaded:,} file(s) to {self.download_dir}")
