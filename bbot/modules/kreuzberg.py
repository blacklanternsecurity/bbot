import pypdfium2
from kreuzberg import extract_file

from bbot.modules.base import BaseModule
from bbot.core.config.models import BaseModuleConfig, Field


class kreuzberg(BaseModule):
    watched_events = ["FILESYSTEM"]
    produced_events = ["RAW_TEXT"]
    flags = ["safe", "passive"]
    meta = {
        "description": "Module to extract data from files",
        "created_date": "2024-06-03",
        "author": "@domwhewell-sage",
    }

    class Config(BaseModuleConfig):
        extensions: list[str] = Field(
            [
                "bak",
                "bash",
                "bashrc",
                "conf",
                "cfg",
                "crt",
                "csv",
                "db",
                "sqlite",
                "doc",
                "docx",
                "ica",
                "indd",
                "ini",
                "json",
                "key",
                "pub",
                "log",
                "markdown",
                "md",
                "odg",
                "odp",
                "ods",
                "odt",
                "pdf",
                "pem",
                "pps",
                "ppsx",
                "ppt",
                "pptx",
                "ps1",
                "rdp",
                "rsa",
                "sh",
                "sql",
                "swp",
                "sxw",
                "txt",
                "vbs",
                "wpd",
                "xls",
                "xlsx",
                "xml",
                "yml",
                "yaml",
            ],
            description="File extensions to parse",
        )

    deps_pip = ["kreuzberg>=4.3,<4.5", "pypdfium2~=5.0"]
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
