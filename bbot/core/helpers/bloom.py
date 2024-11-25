import os
import mmh3
import mmap


class BloomFilter:
    """
    Simple bloom filter implementation capable of roughly 400K lookups/s.

    BBOT uses bloom filters in scenarios like DNS brute-forcing, where it's useful to keep track
    of which mutations have been tried so far.

    A 100-megabyte bloom filter (800M bits) can store 10M entries with a .01% false-positive rate.
    A python hash is 36 bytes. So if you wanted to store these in a set, this would take up
    36 * 10M * 2 (key+value) == 720 megabytes. So we save roughly 7 times the space.
    """

    def __init__(self, size=8000000):
        self.size = size  # total bits
        self.byte_size = (size + 7) // 8  # calculate byte size needed for the given number of bits

        # Create an anonymous mmap region, compatible with both Windows and Unix
        if os.name == "nt":  # Windows
            # -1 indicates an anonymous memory map in Windows
            self.mmap_file = mmap.mmap(-1, self.byte_size)
        else:  # Unix/Linux
            # Use MAP_ANONYMOUS along with MAP_SHARED
            self.mmap_file = mmap.mmap(-1, self.byte_size, prot=mmap.PROT_WRITE, flags=mmap.MAP_ANON | mmap.MAP_SHARED)

        self.clear_all_bits()

    def add(self, item):
        for hash_value in self._hashes(item):
            index = hash_value // 8
            position = hash_value % 8
            current_byte = self.mmap_file[index]
            self.mmap_file[index] = current_byte | (1 << position)

    def check(self, item):
        for hash_value in self._hashes(item):
            index = hash_value // 8
            position = hash_value % 8
            current_byte = self.mmap_file[index]
            if not (current_byte & (1 << position)):
                return False
        return True

    def clear_all_bits(self):
        self.mmap_file.seek(0)
        # Write zeros across the entire mmap length
        self.mmap_file.write(b"\x00" * self.byte_size)

    def _hashes(self, item):
        if not isinstance(item, bytes):
            if not isinstance(item, str):
                item = str(item)
            item = item.encode("utf-8")
        return [abs(hash(item)) % self.size, abs(mmh3.hash(item)) % self.size, abs(self._fnv1a_hash(item)) % self.size]

    def _fnv1a_hash(self, data):
        hash = 0x811C9DC5  # 2166136261
        for byte in data:
            hash ^= byte
            hash = (hash * 0x01000193) % 2**32  # 16777619
        return hash

    def close(self):
        """Explicitly close the memory-mapped file."""
        self.mmap_file.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def __contains__(self, item):
        return self.check(item)
