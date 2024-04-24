import mmh3
from bitarray import bitarray


class BloomFilter:
    """
    Simple bloom filter implementation capable of rougly 200K lookups/s.

    BBOT uses bloom filters in scenarios like dns brute-forcing, where it's useful to keep track
    of which mutations have been tried so far.

    A 100-megabyte bloom filter (800M bits) can store 10M entries with a .01% false-positive rate.
    A python hash is 36 bytes. So if you wanted to store these in a set, this would take up
    36 * 10M * 2 (key+value) == 720 megabytes. So we save rougly 7 times the space.
    """

    def __init__(self, size=2**16):
        self.size = size
        self.bit_array = bitarray(size)
        self.bit_array.setall(0)  # Initialize all bits to 0

    def _hashes(self, item):
        item_str = str(item).encode("utf-8")
        return [
            abs(hash(item)) % self.size,
            abs(mmh3.hash(item_str)) % self.size,
            abs(self._fnv1a_hash(item_str)) % self.size,
        ]

    def _fnv1a_hash(self, data):
        hash = 0x811C9DC5  # 2166136261
        for byte in data:
            hash ^= byte
            hash = (hash * 0x01000193) % 2**32  # 16777619
        return hash

    def add(self, item):
        for hash_value in self._hashes(item):
            self.bit_array[hash_value] = 1

    def check(self, item):
        return all(self.bit_array[hash_value] for hash_value in self._hashes(item))

    def __contains__(self, item):
        return self.check(item)
