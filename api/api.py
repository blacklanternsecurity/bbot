#!/usr/bin/env python3

from fastapi import FastAPI
from typing import Set, List
from pydantic import BaseModel


from db import get_collection, insert_event


class Event(BaseModel):
    id: str
    type: str
    data: str
    module: str
    source: str


class EventInDB(BaseModel):
    _id: str
    type: str
    data: str
    module: str
    sources: Set[str]


# FastAPI specific code
app = FastAPI()


@app.get("/events", response_model=List[EventInDB])
def get_events():
    collection = get_collection()
    return list(collection.find({}))


@app.put("/events")
def put_event(event: Event):
    return insert_event(event.dict())
