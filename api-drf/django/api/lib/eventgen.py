import uuid
import string
import random
import logging
from string import ascii_lowercase

log = logging.getLogger(__name__)

class EventGenerator:
    chars = [c.encode() for c in ascii_lowercase]
    def gen_str(self, min_len=5, max_len=10):
        return b"".join([random.choice(self.chars) for i in range(random.randint(min_len, max_len))])

    def gen_ext(self):
        return random.choice([b".html", b".php", b".aspx", b"/", b".zip", b".txt", b".config"])

    def gen_tld(self):
        return random.choice([b".com", b".net", b".org"])

    def gen_domain(self):
        return self.gen_str() + self.gen_tld()
    
    def gen_ip(self):
        return b".".join([bytes([random.choice(range(0, 256))]) for _ in range(0, 4)])

    def gen_port(self):
        return random.choice(range(0, 65536))

    def gen_url(self):
        return b"/" + self.gen_str() + self.gen_ext()

    def gen_proto(self):
        return random.choice([b"http", b"https"])

    def create_event(self, event_type, module, data, source=None):
        from api.urls import Event
        e = Event(
            type = event_type,
            data = data,
            module = module,
        )
#       if source is not None:
#           e.source.add(source)

        return e
