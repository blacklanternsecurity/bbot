#!/usr/bin/env python3

import sys
import asyncio
import websockets


async def ws_send(message, host, port):
    headers = {"Authorization": "Bearer f4b4a2df3759749bc88da89d590b547fc16d4cf6"}
    url = f"ws://{host}:{port}/ws/foo/"
    async with websockets.connect(url, extra_headers=headers) as ws:
        await ws.send(message)
        # await ws.recv()


def main():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    loop.run_until_complete(ws_send("foo", "localhost", 80))


if __name__ == "__main__":
    sys.exit(main())
