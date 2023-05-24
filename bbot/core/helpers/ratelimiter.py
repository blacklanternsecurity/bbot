import time
import asyncio
import logging

log = logging.getLogger("bbot.helpers.ratelimiter")


class RateLimiter:
    def __init__(self, rate):
        self.rate = rate / 10
        self.current_timestamp = time.time()
        self.count = 0
        self.lock = asyncio.Lock()

    async def __aenter__(self):
        async with self.lock:
            while True:
                if time.time() - self.current_timestamp >= 0.1:
                    # A new 0.1 second interval has begun, reset the count and timestamp
                    self.current_timestamp = time.time()
                    self.count = 1
                    break
                elif self.count < self.rate:
                    # Still within the rate limit for the current 0.1 second interval
                    self.count += 1
                    break
                else:
                    # Rate limit for the current 0.1 second interval has been reached, wait until the next interval
                    await asyncio.sleep(self.current_timestamp + 0.1 - time.time())

        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass
