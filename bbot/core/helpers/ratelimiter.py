import time
import asyncio
import logging

log = logging.getLogger("bbot.helpers.ratelimiter")


class RateLimiter:
    """
    An asynchronous rate limiter class designed to be used as a context manager.

    Args:
        rate (int): The number of allowed requests per second.
        name (str): The name of the rate limiter, used for logging.

    Examples:
        >>> rate_limiter = RateLimiter(100, "web")
        >>> async def rate_limited_request(url):
        ...     async with rate_limiter:
        ...         return await request(url)
    """

    def __init__(self, rate, name):
        self.rate = rate / 10
        self.name = name
        self.log_interval = 10
        self.current_timestamp = time.time()
        self.count = 0
        self.lock = asyncio.Lock()
        self.last_notification = None

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
                    now = time.time()
                    if self.last_notification is None or now - self.last_notification >= self.log_interval:
                        log.verbose(f"{self.name} rate limit threshold ({self.rate*10:.1f}/s) reached")
                        self.last_notification = now
                    # Rate limit for the current 0.1 second interval has been reached, wait until the next interval
                    await asyncio.sleep(self.current_timestamp + 0.1 - time.time())

        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass
