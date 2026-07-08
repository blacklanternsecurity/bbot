import xxhash
import re

_non_word_re = re.compile(r"[^\w]+")


class SimHashHelper:
    def __init__(self, bits=64):
        self.bits = bits

    @staticmethod
    def compute_simhash(text, bits=64, truncate=True, normalization_filter=None):
        """
        Static method for computing a SimHash fingerprint.

        Designed to be called via run_in_executor_cpu(): the work is short and the
        input is truncated to ~3KB inside the helper, so a thread pool avoids the
        pickle/spawn overhead of a process pool.

        Args:
            text (str): The text to hash
            bits (int): Number of bits for the hash. Defaults to 64.
            truncate (bool): Whether to truncate large text for performance. Defaults to True.
            normalization_filter (str): Text to remove for normalization. Defaults to None.

        Returns:
            int: The SimHash fingerprint
        """
        helper = SimHashHelper(bits=bits)
        return helper.hash(text, truncate=truncate, normalization_filter=normalization_filter)

    def _truncate_content(self, content):
        """
        Truncate large content for similarity comparison to improve performance.

        Truncation rules:
        - If content <= 3072 bytes: return as-is
        - If content > 3072 bytes: return first 2048 bytes + last 1024 bytes
        """
        content_length = len(content)

        # No truncation needed for smaller content
        if content_length <= 3072:
            return content

        # Truncate: first 2048 + last 1024 bytes
        first_part = content[:2048]
        last_part = content[-1024:]

        return first_part + last_part

    def _normalize_text(self, text, normalization_filter):
        """
        Normalize text by removing the normalization filter from the text.
        """
        return text.replace(normalization_filter, "")

    def _get_features(self, text):
        """Extract 3-character shingles as features"""
        width = 3
        text = text.lower()
        # Remove non-word characters
        text = _non_word_re.sub("", text)
        # Create 3-character shingles
        return [text[i : i + width] for i in range(max(len(text) - width + 1, 1))]

    def _hash_feature(self, feature):
        """Return a hash of a feature using xxHash"""
        return xxhash.xxh64(feature.encode("utf-8")).intdigest()

    def hash(self, text, truncate=True, normalization_filter=None):
        """
        Generate a SimHash fingerprint for the given text.

        Args:
            text (str): The text to hash
            truncate (bool): Whether to truncate large text for performance. Defaults to True.
                When enabled, text larger than 4KB is truncated to first 2KB + last 1KB for comparison.

        Returns:
            int: The SimHash fingerprint
        """
        # Apply truncation if enabled
        if truncate:
            text = self._truncate_content(text)

        if normalization_filter:
            text = self._normalize_text(text, normalization_filter)

        vector = [0] * self.bits
        features = self._get_features(text)

        for feature in features:
            hv = self._hash_feature(feature)
            for i in range(self.bits):
                bit = (hv >> i) & 1
                vector[i] += 1 if bit else -1

        # Final fingerprint
        fingerprint = 0
        for i, val in enumerate(vector):
            if val >= 0:
                fingerprint |= 1 << i
        return fingerprint

    def similarity(self, hash1, hash2):
        """
        Compute similarity between two SimHashes as a value between 0.0 and 1.0.
        """
        # Hamming distance: count of differing bits
        diff = (hash1 ^ hash2).bit_count()
        return 1.0 - (diff / self.bits)


# Module-level alias for the static method to enable clean imports
compute_simhash = SimHashHelper.compute_simhash
