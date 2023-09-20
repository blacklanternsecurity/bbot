from pathlib import Path

from bbot.modules.base import BaseModule


class filedownload(BaseModule):
    """
    Watch for common filetypes and download them
    """

    watched_events = ["URL_UNVERIFIED"]
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
            "cr2",  #  Canon RAW Image
            "crt",  #  Certificate File
            "crw",  #  Canon RAW Image (Older Format)
            "csv",  #  Comma Separated Values File
            "db",  #  SQLite Database File
            "sqlite",  #  SQLite Database File
            "doc",  #  Microsoft Word Document (Old Format)
            "docx",  #  Microsoft Word Document
            "ica",  #  Citrix Independent Computing Architecture File
            "indd",  #  Adobe InDesign Document
            "ini",  #  Initialization File
            "jar",  #  Java Archive
            "jpg",  #  JPEG Image
            "jpeg",  #  JPEG Image
            "js",  #  JavaScript File
            "json",  #  JavaScript Object Notation File
            "key",  #  Private Key File
            "pub",  #  Public Key File
            "log",  #  Log File
            "md",  #  Markdown File
            "markdown",  #  Markdown File
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
            "svg",  #  Scalable Vector Graphics
            "svgz",  #  Compressed SVG
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
        self.files_downloaded = 0
        return True

    async def handle_event(self, event):
        url_lower = event.data.lower()
        if any(url_lower.endswith(f".{e}") for e in self.extensions):
            timestamp = self.helpers.make_date(event.timestamp)
            filepath = Path(event.parsed.path)
            filename_stem = self.helpers.tagify(filepath.stem)
            filename = f"{timestamp}_{filename_stem}{filepath.suffix}"
            file_destination = self.download_dir / filename
            base_url = f"{event.parsed.scheme}://{event.parsed.netloc}"
            self.info(f'Found "{filepath.name}" at "{base_url}", downloading to {file_destination}')
            await self.helpers.download(event.data, filename=file_destination, max_size=self.max_filesize)
            self.files_downloaded += 1

    async def report(self):
        if self.files_downloaded > 0:
            self.success(f"Downloaded {self.files_downloaded:,} file(s) to {self.download_dir}")
