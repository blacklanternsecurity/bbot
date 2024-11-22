from typing import List
from bbot import Scanner
from fastapi import FastAPI, Query

app = FastAPI()


@app.get("/start")
async def start(targets: List[str] = Query(...)):
    scanner = Scanner(*targets, modules=["httpx"])
    events = [e async for e in scanner.async_start()]
    return [e.json() for e in events]


@app.get("/ping")
async def ping():
    return {"status": "ok"}
