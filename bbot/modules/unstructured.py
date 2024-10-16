import os

from bbot.modules.base import BaseModule


class unstructured(BaseModule):
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

    deps_apt = ["libmagic-dev", "poppler-utils", "tesseract-ocr", "libreoffice", "pandoc"]
    deps_pip = ["unstructured[all-docs]>=0.15.7,<1.0", "nltk>=3.9.0,<4.0"]

    scope_distance_modifier = 1

    async def setup(self):
        self.extensions = list(set([e.lower().strip(".") for e in self.config.get("extensions", [])]))
        # Do not send user statistics to the unstructured library
        os.environ["SCARF_NO_ANALYTICS"] = "true"
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
        content = await self.scan.helpers.run_in_executor_mp(extract_text, file_path)
        if content:
            raw_text_event = self.make_event(
                content,
                "RAW_TEXT",
                context=f"Extracted text from {file_path}",
                parent=event,
            )
            await self.emit_event(raw_text_event)

    async def finish(self):
        del os.environ["SCARF_NO_ANALYTICS"]
        return


def extract_text(file_path):
    """
    extract_text Extracts plaintext from a document path using unstructured.

    :param file_path: The path of the file to extract text from.
    :return: ASCII-encoded plaintext extracted from the document.
    """

    from unstructured.partition.auto import partition

    unstructured_file_types = [
        ".csv",
        ".eml",
        ".msg",
        ".epub",
        ".xlsx",
        ".xls",
        ".html",
        ".htm",
        ".md",
        ".org",
        ".odt",
        ".pdf",
        ".txt",
        ".text",
        ".log",
        ".ppt",
        ".pptx",
        ".rst",
        ".rtf",
        ".tsv",
        ".doc",
        ".docx",
        ".xml",
    ]

    # If the file can be extracted with unstructured use its partition function or try and read it
    if any(file_path.lower().endswith(file_type) for file_type in unstructured_file_types):
        try:
            elements = partition(filename=file_path)
            return "\n\n".join(element.text for element in elements)
        except ValueError:
            with open(file_path, "rb") as file:
                return file.read().decode("utf-8", errors="ignore")
    else:
        with open(file_path, "rb") as file:
            return file.read().decode("utf-8", errors="ignore")
