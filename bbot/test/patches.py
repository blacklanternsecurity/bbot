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


def patch_commands():
    def run(*args, **kwargs):
        text = kwargs.get("text", True)
        if text:
            return '{"test": "test"}\n'
        else:
            return b'{"test": "test"}\n'

    def run_live(*args, **kwargs):
        yield '{"test": "test"}'

    from bbot.core.helpers import command

    command.run = run
    command.run_live = run_live
    from bbot.core.helpers import helper

    helper.ConfigAwareHelper.run = run
    helper.ConfigAwareHelper.run_live = run_live
