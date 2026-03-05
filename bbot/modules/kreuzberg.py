import pypdfium2
from kreuzberg import extract_file

from bbot.modules.base import BaseModule


class kreuzberg(BaseModule):
    watched_events = ["FILESYSTEM"]
    produced_events = ["RAW_TEXT"]
    flags = ["passive", "safe"]
    meta = {
        "description": "Module to extract data from files",
        "created_date": "2024-06-03",
        "author": "@domwhewell-sage",
    }
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
            "ica",  #  Citrix Independent Computing Architecture File
            "indd",  #  Adobe InDesign Document
            "ini",  #  Initialization File
            "json",  #  JSON File
            "key",  #  Private Key File
            "pub",  #  Public Key File
            "log",  #  Log File
            "markdown",  #  Markdown File
            "md",  #  Markdown File
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
            "rdp",  #  Remote Desktop Protocol File
            "rsa",  #  RSA Private Key File
            "sh",  #  Shell Script
            "sql",  #  SQL Database Dump
            "swp",  #  Swap File (temporary file, often Vim)
            "sxw",  #  OpenOffice.org Writer document
            "txt",  #  Plain Text Document
            "vbs",  #  Visual Basic Script
            "wpd",  #  WordPerfect Document
            "xls",  #  Microsoft Excel Spreadsheet (Old Format)
            "xlsx",  #  Microsoft Excel Spreadsheet
            "xml",  #  eXtensible Markup Language File
            "yml",  #  YAML Ain't Markup Language
            "yaml",  #  YAML Ain't Markup Language
        ],
    }
    options_desc = {
        "extensions": "File extensions to parse",
    }

    deps_pip = ["kreuzberg~=4.3", "pypdfium2~=5.0"]
    scope_distance_modifier = 1

    async def setup(self):
        self.extensions = list({e.lower().strip(".") for e in self.config.get("extensions", [])})
        return True

    async def filter_event(self, event):
        if "file" in event.tags:
            if not any(event.data["path"].endswith(f".{ext}") for ext in self.extensions):
                return False, "File extension not in the allowed list"
        else:
            return False, "Event is not a file"
        return True

    async def handle_event(self, event):
        file_path = event.data["path"]
        try:
            if file_path.lower().endswith(".pdf"):
                content = await self.helpers.run_in_executor_mp(self.extract_pdf, file_path)
            else:
                result = await extract_file(file_path)
                content = result.content.strip()
        except Exception as e:
            import traceback

            self.error(f"Error extracting text from {file_path}: {e}")
            self.trace(traceback.format_exc())
            return

        if content:
            raw_text_event = self.make_event(
                content,
                "RAW_TEXT",
                context=f"Extracted text from {file_path}",
                parent=event,
            )
            await self.emit_event(raw_text_event)

    @staticmethod
    def extract_pdf(file_path):
        """Extract text from PDF using pypdfium2 directly instead of kreuzberg.

        kreuzberg's bundled pdfium extracts text spatially via get_text_bounded(), which
        clips long unbroken strings (JWTs, base64, URLs) that extend beyond the page width.
        pypdfium2's get_text_range() extracts by character index, returning complete text
        regardless of spatial position.
        """
        document = pypdfium2.PdfDocument(file_path)
        try:
            pages = []
            for page in document:
                textpage = page.get_textpage()
                text = textpage.get_text_range()
                pages.append(text)
            return " ".join("\n".join(pages).strip().split())
        finally:
            document.close()
