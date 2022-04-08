from pathlib import Path

from bbot import config as default_config
from bbot.scanner import Scanner
from bbot.core.configurator import available_modules

from omegaconf import OmegaConf

test_config = OmegaConf.load(Path(__file__).parent / "test.conf")
config = OmegaConf.merge(default_config, test_config)

scan = Scanner("test", modules=list(available_modules), config={"max_threads": 250})
helpers = scan.helpers

ipv4_event = scan.make_event("192.168.1.1", dummy=True)
netv4_event = scan.make_event("192.168.1.1/24", dummy=True)
ipv6_event = scan.make_event("dead::beef", dummy=True)
netv6_event = scan.make_event("dead::beef/64", dummy=True)
domain_event = scan.make_event("evilcorp.com", dummy=True)
subdomain_event = scan.make_event("www.evilcorp.com", dummy=True)
open_port_event = scan.make_event("port.www.evilcorp.com:777", dummy=True)
ipv4_open_port_event = scan.make_event("192.168.1.1:80", dummy=True)
ipv6_open_port_event = scan.make_event("[dead::beef]:80", "OPEN_TCP_PORT", dummy=True)
url_event = scan.make_event("https://url.www.evilcorp.com:666/hellofriend", dummy=True)
ipv4_url_event = scan.make_event("https://192.168.1.1:666/hellofriend", dummy=True)
ipv6_url_event = scan.make_event("https://[dead::beef]:666/hellofriend", "URL", dummy=True)
emoji_event = scan.make_event("💩", "WHERE_IS_YOUR_GOD_NOW", dummy=True)


test_events = {
    "IPV4_ADDRESS": (ipv4_event,),
    "IPV6_ADDRESS": (ipv6_event,),
    "IPV4_RANGE": (netv4_event,),
    "IPV6_RANGE": (netv6_event,),
    "DNS_NAME": (domain_event, subdomain_event),
    "OPEN_TCP_PORT": (open_port_event, ipv4_open_port_event, ipv6_open_port_event),
    "URL": (url_event, ipv4_url_event, ipv6_url_event),
}
