def test_threadpool():
    from concurrent.futures import ThreadPoolExecutor
    from bbot.core.helpers.threadpool import ThreadPoolWrapper, NamedLock, as_completed

    with ThreadPoolExecutor(max_workers=3) as executor:
        pool = ThreadPoolWrapper(executor)
        add_one = lambda x: x + 1
        futures = [pool.submit_task(add_one, y) for y in [0, 1, 2, 3, 4]]
        results = []
        for f in as_completed(futures):
            results.append(f.result())
        assert tuple(sorted(results)) == (1, 2, 3, 4, 5)

    nl = NamedLock(max_size=5)
    for i in range(50):
        nl.get_lock(str(i))
    assert len(nl._cache) == 5
    assert tuple(nl._cache.keys()) == tuple(hash(str(x)) for x in [45, 46, 47, 48, 49])
