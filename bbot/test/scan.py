from pathlib import Path
from omegaconf import OmegaConf

from bbot.scanner import Scanner
from bbot import config as default_config
from bbot.core.configurator import available_modules

test_config = OmegaConf.load(Path(__file__).parent / "test.conf")
config = OmegaConf.merge(default_config, test_config)

scan = Scanner("scanme.nmap.org", modules=list(available_modules), config=config)
helpers = scan.helpers

ipv4_event = scan.make_event("8.8.8.8", dummy=True)
netv4_event = scan.make_event("8.8.8.8/30", dummy=True)
ipv6_event = scan.make_event("2001:4860:4860::8888", dummy=True)
netv6_event = scan.make_event("2001:4860:4860::8888/126", dummy=True)
domain_event = scan.make_event("publicAPIs.org", dummy=True)
subdomain_event = scan.make_event("api.publicAPIs.org", dummy=True)
open_port_event = scan.make_event("api.publicAPIs.org:443", dummy=True)
ipv4_open_port_event = scan.make_event("8.8.8.8:443", dummy=True)
ipv6_open_port_event = scan.make_event("[2001:4860:4860::8888]:443", "OPEN_TCP_PORT", dummy=True)
url_event = scan.make_event("https://api.publicAPIs.org:443/hellofriend", dummy=True)
ipv4_url_event = scan.make_event("https://8.8.8.8:443/hellofriend", dummy=True)
ipv6_url_event = scan.make_event("https://[2001:4860:4860::8888]:443/hellofriend", "URL", dummy=True)
url_hint_event = scan.make_event("https://api.publicAPIs.org:443/hello.ash", "URL_HINT", dummy=True)
emoji_event = scan.make_event("💩", "WHERE_IS_YOUR_GOD_NOW", dummy=True)

all_events = [
    ipv4_event,
    netv4_event,
    ipv6_event,
    netv6_event,
    domain_event,
    subdomain_event,
    open_port_event,
    ipv4_open_port_event,
    ipv6_open_port_event,
    url_event,
    ipv4_url_event,
    ipv6_url_event,
    emoji_event,
]
