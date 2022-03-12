import os
import psutil
import signal
import logging
import wordninja
import tldextract as _tldextract
from itertools import combinations
from hashlib import sha1 as hashlib_sha1

from .regexes import word_regexes

log = logging.getLogger('bbot.core.helpers')

def is_domain(d):
    extracted = tldextract(d)
    if extracted.domain and not extracted.subdomain:
        return True
    return False


def is_subdomain(d):
    extracted = tldextract(d)
    if extracted.domain and extracted.subdomain:
        return True
    return False


def sha1(data):
    if type(data) != bytes:
        data = str(data).encode('utf-8', errors='ignore')
    return hashlib_sha1(data)


def smart_decode(data):
    if type(data) == bytes:
        return data.decode('utf-8', errors='ignore')
    else:
        return str(data)


def tldextract(data):
    return _tldextract.extract(smart_decode(data))


def extract_words(data, max_length=100):
    '''
    Intelligently extract words from given data
    '''
    words = set()
    data = smart_decode(data)

    for r in word_regexes:
        for word in set(r.findall(data)):
            # blacklanternsecurity
            if len(word) <= max_length:
                words.add(word)

    # blacklanternsecurity --> ['black', 'lantern', 'security']
    max_slice_length = 3
    for word in list(words):
        subwords = wordninja.split(word)
        # blacklanternsecurity --> ['black', 'lantern', 'security', 'blacklantern', 'lanternsecurity']
        for s, e in combinations(range(len(subwords)+1), 2):
            if e-s <= max_slice_length:
                subword_slice = ''.join(subwords[s:e])
                words.add(subword_slice)

    return words


def kill_children(parent_pid=None, sig=signal.SIGTERM):
    '''
    Forgive me father for I have sinned
    '''
    try:
        parent = psutil.Process(parent_pid)
    except psutil.NoSuchProcess:
        log.warning(f'No such PID: {parent_pid}')
    log.debug(f'Killing children of process ID {parent.pid}')
    children = parent.children(recursive=True)
    for child in children:
        log.debug(f'Killing child with PID {child.pid}')
        if child.name != 'python':
            child.send_signal(sig)