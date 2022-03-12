import logging
import ipaddress
from contextlib import suppress

from bbot.core.regexes import event_type_regexes, event_id_regex
from bbot.core.helpers import sha1, is_domain, is_subdomain, smart_decode

log = logging.getLogger('bbot.core.event.helpers')

def sanitize_ip_address(d):
    return f'{ipaddress.ip_address(d)}'

def sanitize_ip_network(d):
    return f'{ipaddress.ip_network(d, strict=False)}'

def sanitize_open_port(d):
    host,port = str(d).split(':')
    port = max(0, min(65535, int(port)))
    host_type = get_event_type(host)
    for sanitizer in event_sanitizers.get(host_type, []):
        host = sanitizer(host)
    return f'{host}:{port}'

event_sanitizers = {
    'DOMAIN': [str.strip, str.lower],
    'SUBDOMAIN': [str.strip, str.lower],
    'EMAIL_ADDRESS': [str.strip, str.lower],
    'IPV4_ADDRESS': [sanitize_ip_address],
    'IPV6_ADDRESS': [sanitize_ip_address],
    'IPV4_RANGE': [sanitize_ip_network],
    'IPV6_RANGE': [sanitize_ip_network],
    'OPEN_TCP_PORT': [sanitize_open_port],
    'OPEN_UDP_PORT': [sanitize_open_port]
}

event_data_constructors = {
    'IPV4_ADDRESS': ipaddress.ip_address,
    'IPV6_ADDRESS': ipaddress.ip_address,
    'IPV4_RANGE': ipaddress.ip_network,
    'IPV6_RANGE': ipaddress.ip_network
}

def get_event_type(data):
    '''
    Attempt to divine event type from data
    '''

    data = smart_decode(data)

    # IP address
    with suppress(Exception):
        ip = ipaddress.ip_address(str(data).strip())
        return f'IPV{ip.version}_ADDRESS'

    # IP network
    with suppress(Exception):
        net = ipaddress.ip_network(str(data).strip(), strict=False)
        return f'IPV{net.version}_RANGE'

    # Everything else
    for t,r in event_type_regexes.items():
        if r.match(data):
            if t == 'HOSTNAME':
                if is_domain(data):
                    return 'DOMAIN'
                else:
                    return 'SUBDOMAIN'
            else:
                return t

def is_event_id(s):
    if event_id_regex.match(str(s)):
        return True
    return False


def make_event_id(data, event_type):
    return f'{sha1(data).hexdigest()}:{event_type}'


ip_types = [
    'IPV4_ADDRESS',
    'IPV4_RANGE',
    'IPV6_ADDRESS',
    'IPV6_RANGE'
]

host_types = [
    'URL'
    'DOMAIN',
    'SUBDOMAIN',
    'EMAIL_ADDRESS'
]

port_types = [
    'OPEN_TCP_PORT',
    'OPEN_UDP_PORT'
]

def event_in_other(event1, event2):

    #log.debug(f'{event1} in {event2}?')

    # if hashes match
    if event2 == event1:
        #log.debug('hashes match')
        return True

    # if events are the same type
    elif event2.type == event1.type:
        #log.debug('same type')
        return event1.data_obj == event2.data_obj or event1.data_obj in event2.data_obj

    # ip addresses
    elif event2.type in ip_types and event1.type in ip_types:
        #log.debug('IPs')
        event2_net = ipaddress.ip_network(event2.data_obj)
        event1_net = ipaddress.ip_network(event1.data_obj)
        if event1.num_addresses <= event2.num_addresses:
            netmask = event2_net.netmask
            event2_net = ipaddress.ip_network(f'{event2_net.network_address}/{netmask}')
            event1_net = ipaddress.ip_network(f'{event2_net.network_address}/{netmask}')
            return event2_net == event1_net

    # urls
    elif event1.type in ['URL']:
        #log.debug('url')
        return event1.host in event2

    # hostnames
    elif event2.type in host_types or event1.type in host_types:
        #log.debug('hostnames')
        other_len = len(event1.host.split('.'))
        self_truncated = '.'.join(event2.host.split('.')[-other_len:])
        return self_truncated == event1.host

    return False