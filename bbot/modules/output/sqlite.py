from pathlib import Path

from bbot.modules.templates.sql import SQLTemplate
from bbot.core.config.models import BaseModuleConfig, Field


class SQLite(SQLTemplate):
    watched_events = ["*"]
    meta = {
        "description": "Output scan data to a SQLite database",
        "created_date": "2024-11-07",
        "author": "@TheTechromancer",
    }

    class Config(BaseModuleConfig):
        database: str = Field("", description="The path to the sqlite database file")
        retries: int = Field(
            10, description="Number of times to retry connecting to the database (1 second between retries)"
        )

    deps_pip = ["sqlmodel", "aiosqlite"]

    async def setup(self):
        db_file = self.config.get("database", "")
        if not db_file:
            db_file = self.scan.home / "output.sqlite"
        db_file = Path(db_file)
        if not db_file.is_absolute():
            db_file = self.scan.home / db_file
        self.db_file = db_file
        self.db_file.parent.mkdir(parents=True, exist_ok=True)
        return await super().setup()

    def connection_string(self, mask_password=False):
        return f"sqlite+aiosqlite:///{self.db_file}"
