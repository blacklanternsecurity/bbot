import urllib3
import requests

from bbot.core.helpers import helper
from bbot.core.helpers import command

example_url = "https://api.publicapis.org/health"
http = urllib3.PoolManager()
urllib_response = http.request("GET", example_url)
requests_response = requests.get(example_url)


def patch_requests(monkeypatch):

    monkeypatch.setattr("urllib3.connectionpool.HTTPConnectionPool.urlopen", lambda *args, **kwargs: urllib_response)
    monkeypatch.setattr("urllib3.poolmanager.PoolManager.urlopen", lambda *args, **kwargs: urllib_response)
    monkeypatch.setattr("requests.adapters.HTTPAdapter.send", lambda *args, **kwargs: requests_response)
    monkeypatch.setattr("bbot.core.helpers.web.request", lambda *args, **kwargs: requests_response)
    monkeypatch.setattr("bbot.core.helpers.web.download", lambda *args, **kwargs: "nope")


sample_output = [
    # httpx
    """{"timestamp":"2022-04-15T17:08:29.436778586-04:00","request":"GET /health HTTP/1.1\\r\\nHost: api.publicapis.org\\r\\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/537.36\\r\\nAccept-Charset: utf-8\\r\\nAccept-Encoding: gzip\\r\\n\\r\\n","response-header":"HTTP/1.1 200 OK\\r\\nConnection: close\\r\\nContent-Length: 15\\r\\nContent-Type: text/plain; charset=utf-8\\r\\nDate: Fri, 15 Apr 2022 21:08:29 GMT\\r\\nServer: Caddy\\r\\nX-Rate-Limit-Duration: 1\\r\\nX-Rate-Limit-Limit: 10.00\\r\\nX-Rate-Limit-Request-Forwarded-For: 50.240.76.25\\r\\nX-Rate-Limit-Request-Remote-Addr: 172.17.0.1:32910\\r\\n\\r\\n","scheme":"https","port":"443","path":"/health","body-sha256":"6c63d4b385b07fe0e09a8a1f95b826e8a7d0401dfd12d649fe7c64b8a785023e","header-sha256":"161187846622dc97219392ab70195f4a477457e55dadf4b39f1b6c734e396120","url":"https://api.publicapis.org:443/health","input":"https://api.publicapis.org/health","webserver":"Caddy","response-body":"{\\"alive\\": true}","content-type":"text/plain","method":"GET","host":"138.197.231.124","content-length":15,"status-code":200,"response-time":"412.587433ms","failed":false,"lines":1,"words":2}""",
    # nuclei
    """{"template":"technologies/tech-detect.yaml","template-url":"https://github.com/projectdiscovery/nuclei-templates/blob/master/technologies/tech-detect.yaml","template-id":"tech-detect","info":{"name":"Wappalyzer Technology Detection","author":["hakluke"],"tags":["tech"],"reference":null,"severity":"info"},"matcher-name":"caddy","type":"http","host":"https://api.publicapis.org/health","matched-at":"https://api.publicapis.org:443/health","ip":"138.197.231.124","timestamp":"2022-04-15T17:09:01.021589723-04:00","curl-command":"curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2226.0 Safari/537.36' 'https://api.publicapis.org/health'","matcher-status":true,"matched-line":null}""",
    # dnsx
    """{"host":"api.publicapis.org","resolver":["1.0.0.1:53"],"a":["138.197.231.124"],"has_internal_ips":false,"status_code":"NOERROR","timestamp":"2022-04-15T17:11:24.746370988-04:00"}""",
    # url
    "https://api.publicapis.org:443/health",
    # open port
    "api.publicapis.org:443",
    # host
    "api.publicapis.org",
]


def patch_commands(monkeypatch):
    def run(*args, **kwargs):
        text = kwargs.get("text", True)
        output = "\n".join(sample_output)
        if text:
            return output
        else:
            return output.encode(errors="ignore")

    def run_live(*args, **kwargs):
        for line in sample_output:
            yield line

    monkeypatch.setattr(command, "run", run)
    monkeypatch.setattr(command, "run_live", run_live)
    monkeypatch.setattr(helper.ConfigAwareHelper, "run", run)
    monkeypatch.setattr(helper.ConfigAwareHelper, "run_live", run_live)
