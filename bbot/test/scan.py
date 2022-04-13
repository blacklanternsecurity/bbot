from pathlib import Path
from omegaconf import OmegaConf

from bbot.scanner import Scanner
from bbot import config as default_config
from bbot.core.configurator import available_modules

test_config = OmegaConf.load(Path(__file__).parent / "test.conf")
config = OmegaConf.merge(default_config, test_config)

scan = Scanner("scanme.nmap.org", modules=list(available_modules), config=config)
helpers = scan.helpers

ipv4_event = scan.make_event("192.168.1.1", dummy=True)
netv4_event = scan.make_event("192.168.1.1/30", dummy=True)
ipv6_event = scan.make_event("dead::beef", dummy=True)
netv6_event = scan.make_event("dead::beef/126", dummy=True)
domain_event = scan.make_event("evilcorp.com", dummy=True)
subdomain_event = scan.make_event("www.evilcorp.com", dummy=True)
open_port_event = scan.make_event("port.www.evilcorp.com:777", dummy=True)
ipv4_open_port_event = scan.make_event("192.168.1.1:80", dummy=True)
ipv6_open_port_event = scan.make_event("[dead::beef]:80", "OPEN_TCP_PORT", dummy=True)
url_event = scan.make_event("https://url.www.evilcorp.com:666/hellofriend", dummy=True)
ipv4_url_event = scan.make_event("https://192.168.1.1:666/hellofriend", dummy=True)
ipv6_url_event = scan.make_event("https://[dead::beef]:666/hellofriend", "URL", dummy=True)
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
