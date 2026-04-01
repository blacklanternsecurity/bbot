"""
Subprocess script for web crawl memory benchmark.

Launches a local HTTP server with NUM_PAGES pages (each BODY_SIZE bytes),
runs a BBOT scan against it, and prints peak tracemalloc memory to stdout.

Invoked by test_scan_memory.py — not meant to be run directly.
"""

import gc
import sys
import asyncio
import threading
import tracemalloc
import importlib.util
from http.server import HTTPServer, BaseHTTPRequestHandler

from bbot.scanner import Scanner

NUM_PAGES = int(sys.argv[1])
BODY_SIZE = int(sys.argv[2])

HTTP_MODULE = "httpx" if importlib.util.find_spec("bbot.modules.httpx") else "http"


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            links = "".join(f'<a href="/page{i}">page{i}</a>' for i in range(NUM_PAGES))
            body = "<html><body>" + links + "</body></html>"
        elif self.path.startswith("/page"):
            i = self.path.replace("/page", "")
            links = f'<a href="/data{i}/info">info</a><a href="/data{i}/details">details</a>'
            body = "<html><body><h1>Page " + i + "</h1>" + links + "A" * BODY_SIZE + "</body></html>"
        elif self.path.startswith("/data"):
            body = "<html><body>data endpoint</body></html>"
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *a):
        pass


server = HTTPServer(("127.0.0.1", 0), H)
port = server.server_address[1]
threading.Thread(target=server.serve_forever, daemon=True).start()

scan = Scanner(
    f"http://127.0.0.1:{port}/",
    modules=[HTTP_MODULE],
    output_modules=["python"],
    config={
        "dns": {"disable": True},
        "scope": {"search_distance": 0},
        "web": {"spider_distance": 10, "spider_depth": 10, "spider_links_per_page": NUM_PAGES},
        "speculate": True,
        "excavate": True,
        "aggregate": False,
        "cloudcheck": False,
    },
    force_start=True,
)


async def run():
    await scan._prep()
    gc.collect()
    if tracemalloc.is_tracing():
        tracemalloc.stop()
    tracemalloc.start()
    events = []
    async for event in scan.async_start():
        events.append(event)


asyncio.run(run())
_, peak = tracemalloc.get_traced_memory()
tracemalloc.stop()
server.shutdown()
print(f"PEAK_MB:{round(peak / 1024 / 1024, 2)}")
