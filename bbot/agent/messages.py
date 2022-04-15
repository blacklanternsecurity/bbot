from uuid import UUID
from pydantic import BaseModel


class Message(BaseModel):
    conversation: UUID
    command: str
    arguments: dict


### COMMANDS ###


class start_scan(BaseModel):
    scan_id: str
    targets: list
    modules: list
    output_modules: list = []
    config: dict = {}


class stop_scan(BaseModel):
    pass


class scan_status(BaseModel):
    pass
