import time
import asyncio
import logging
from collections import deque

log = logging.getLogger("bbot.helpers.ratelimiter")


class RateLimiter:
    def __init__(self, rate):
        self.rate = rate
        self.timestamps = deque()
        self.lock = asyncio.Lock()

    async def __aenter__(self):
        async with self.lock:
            while True:
                while len(self.timestamps) >= self.rate:
                    time_diff = time.time() - self.timestamps[0]
                    if time_diff < 1.0:
                        sleep_duration = 1.0 - time_diff
                        await asyncio.sleep(sleep_duration)
                    self.timestamps.popleft()

                # Check if adding a new request will not exceed the rate limit
                if len(self.timestamps) < self.rate:
                    self.timestamps.append(time.time())
                    break
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass
