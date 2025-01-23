import time
import pytest
import string
import random


@pytest.mark.asyncio
async def test_bloom_filter():
    def generate_random_strings(n, length=10):
        """Generate a list of n random strings."""
        return ["".join(random.choices(string.ascii_letters + string.digits, k=length)) for _ in range(n)]

    from bbot.scanner import Scanner

    scan = Scanner()

    n_items_to_add = 100000
    n_items_to_test = 100000
    bloom_filter_size = 8000000

    # Initialize the simple bloom filter and the set
    bloom_filter = scan.helpers.bloom_filter(size=bloom_filter_size)

    test_set = set()

    # Generate random strings to add
    print(f"Generating {n_items_to_add:,} items to add")
    items_to_add = set(generate_random_strings(n_items_to_add))

    # Generate random strings to test
    print(f"Generating {n_items_to_test:,} items to test")
    items_to_test = generate_random_strings(n_items_to_test)

    print("Adding items")
    start = time.time()
    for item in items_to_add:
        bloom_filter.add(item)
        test_set.add(hash(item))
    end = time.time()
    elapsed = end - start
    print(f"elapsed: {elapsed:.2f} ({int(n_items_to_test / elapsed)}/s)")
    # this shouldn't take longer than 5 seconds
    assert elapsed < 5

    # make sure we have 100% accuracy
    start = time.time()
    for item in items_to_add:
        assert item in bloom_filter
    end = time.time()
    elapsed = end - start
    print(f"elapsed: {elapsed:.2f} ({int(n_items_to_test / elapsed)}/s)")
    # this shouldn't take longer than 5 seconds
    assert elapsed < 5

    print("Measuring false positives")
    # Check for false positives
    false_positives = 0
    for item in items_to_test:
        if bloom_filter.check(item) and hash(item) not in test_set:
            false_positives += 1
    false_positive_percent = false_positives / len(items_to_test) * 100

    print(f"False positive rate: {false_positive_percent:.2f}% ({false_positives}/{len(items_to_test)})")

    # ensure false positives are less than .02 percent
    assert false_positive_percent < 0.02

    bloom_filter.close()

    await scan._cleanup()
