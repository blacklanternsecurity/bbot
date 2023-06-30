from uuid import UUID
from typing import Optional
from pydantic import BaseModel


class Message(BaseModel):
    conversation: UUID
    command: str
    arguments: Optional[dict] = {}


### COMMANDS ###


class start_scan(BaseModel):
    scan_id: str
    targets: list
    modules: list
    output_modules: list = []
    config: dict = {}
    name: Optional[str] = None


class stop_scan(BaseModel):
    pass


class scan_status(BaseModel):
    pass
