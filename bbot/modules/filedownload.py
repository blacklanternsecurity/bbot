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
    produced_events = []
    flags = ["active", "safe"]
    meta = {"description": "Download common filetypes such as PDF, DOCX, PPTX, etc."}
    options = {
        "extensions": [
            "bak",  #  Backup File
            "bash",  #  Bash Script or Configuration
            "bashrc",  #  Bash Script or Configuration
            "conf",  #  Configuration File
            "cfg",  #  Configuration File
            "crt",  #  Certificate File
            "csv",  #  Comma Separated Values File
            "db",  #  SQLite Database File
            "sqlite",  #  SQLite Database File
            "doc",  #  Microsoft Word Document (Old Format)
            "docx",  #  Microsoft Word Document
            "exe",  #  Windows PE executable
            "ica",  #  Citrix Independent Computing Architecture File
            "indd",  #  Adobe InDesign Document
            "ini",  #  Initialization File
            "jar",  #  Java Archive
            "key",  #  Private Key File
            "pub",  #  Public Key File
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
            "png",  #  Portable Network Graphics Image
            "pps",  #  Microsoft PowerPoint Slideshow (Old Format)
            "ppsx",  #  Microsoft PowerPoint Slideshow
            "ppt",  #  Microsoft PowerPoint Presentation (Old Format)
            "pptx",  #  Microsoft PowerPoint Presentation
            "ps1",  #  PowerShell Script
            "raw",  #  Raw Image File Format
            "rdp",  #  Remote Desktop Protocol File
            "sh",  #  Shell Script
            "sql",  #  SQL Database Dump
            "swp",  #  Swap File (temporary file, often Vim)
            "sxw",  #  OpenOffice.org Writer document
            "tar",  #  Tar Archive
            "tar.gz",  # Gzip-Compressed Tar Archive
            "zip",  #  Zip Archive
            "txt",  #  Plain Text Document
            "vbs",  #  Visual Basic Script
            "wpd",  #  WordPerfect Document
            "xls",  #  Microsoft Excel Spreadsheet (Old Format)
            "xlsx",  #  Microsoft Excel Spreadsheet
            "xml",  #  eXtensible Markup Language File
            "yml",  #  YAML Ain't Markup Language
            "yaml",  #  YAML Ain't Markup Language
        ],
        "max_filesize": "10MB",
    }
    options_desc = {
        "extensions": "File extensions to download",
        "max_filesize": "Cancel download if filesize is greater than this size",
    }

    scope_distance_modifier = 1

    async def setup(self):
        self.extensions = list(set([e.lower().strip(".") for e in self.options.get("extensions", [])]))
        self.max_filesize = self.options.get("max_filesize", "10MB")
        self.download_dir = self.scan.home / "filedownload"
        self.helpers.mkdir(self.download_dir)
        self.files_downloaded = set()
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
        h = self.hash_event(event)
        if h in self.files_downloaded:
            return False, f"Already processed {event}"
        return True

    def hash_event(self, event):
        if event.type == "HTTP_RESPONSE":
            return hash(event.data["url"])
        return hash(event.data)

    async def handle_event(self, event):
        if event.type == "URL_UNVERIFIED":
            url_lower = event.data.lower()
            if any(url_lower.endswith(f".{e}") for e in self.extensions):
                await self.download_file(event.data)
        elif event.type == "HTTP_RESPONSE":
            content_type = event.data["header"].get("content_type", "")
            if content_type:
                url = event.data["url"]
                await self.download_file(url, content_type=content_type)

    async def download_file(self, url, content_type=None):
        orig_filename, file_destination, base_url = self.make_filename(url, content_type=content_type)
        if orig_filename is None:
            return
        result = await self.helpers.download(url, warn=False, filename=file_destination, max_size=self.max_filesize)
        if result:
            self.info(f'Found "{orig_filename}" at "{base_url}", downloaded to {file_destination}')
        self.files_downloaded.add(hash(url))

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
        return orig_filename, self.download_dir / filename, base_url

    async def report(self):
        if self.files_downloaded:
            self.success(f"Downloaded {len(self.files_downloaded):,} file(s) to {self.download_dir}")
