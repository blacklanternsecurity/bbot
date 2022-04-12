def patch_requests():
    import urllib3
    import requests

    example_url = "https://example.com"
    http = urllib3.PoolManager()
    resp1 = http.request("GET", example_url)
    resp2 = requests.get(example_url)

    urllib3.connectionpool.urlopen = lambda *args, **kwargs: resp1
    urllib3.poolmanager.PoolManager.urlopen = lambda *args, **kwargs: resp1

    requests.adapters.HTTPAdapter.send = lambda *args, **kwargs: resp2
