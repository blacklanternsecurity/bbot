import json
import asyncio
import ssl
from urllib.request import urlopen, Request
from urllib.error import URLError
from base64 import b64encode

from .base import ModuleTestBase
from bbot.test.worker import wait_for_container


def _elastic_request(method, url, body=None):
    """Make a request to Elasticsearch with basic auth, ignoring SSL verification."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    creds = b64encode(b"elastic:bbotislife").decode()
    headers = {"Authorization": f"Basic {creds}"}
    if body is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(body).encode() if isinstance(body, dict) else body.encode()
    req = Request(url, data=body, headers=headers, method=method)
    return urlopen(req, context=ctx)


class TestElastic(ModuleTestBase):
    config_overrides = {
        "modules": {
            "elastic": {
                "url": "https://localhost:9200/bbot_test_events/_doc",
                "username": "elastic",
                "password": "bbotislife",
            }
        }
    }
    skip_distro_tests = True

    async def setup_before_prep(self, module_test):
        # Start Elasticsearch container
        await asyncio.create_subprocess_exec(
            "docker",
            "run",
            "--name",
            "bbot-test-elastic",
            "--rm",
            "-e",
            "ELASTIC_PASSWORD=bbotislife",
            "-e",
            "cluster.routing.allocation.disk.watermark.low=96%",
            "-e",
            "cluster.routing.allocation.disk.watermark.high=97%",
            "-e",
            "cluster.routing.allocation.disk.watermark.flood_stage=98%",
            "-p",
            "9200:9200",
            "-d",
            "docker.elastic.co/elasticsearch/elasticsearch:8.16.0",
        )

        await wait_for_container(
            "Elasticsearch", lambda: _elastic_request("GET", "https://localhost:9200/_cat/health").read()
        )

        # Ensure the index is empty
        try:
            _elastic_request("DELETE", "https://localhost:9200/bbot_test_events")
        except URLError:
            pass  # Index might not exist yet

    async def check(self, module_test, events):
        try:
            from bbot.models.pydantic import Event

            events_json = [e.json() for e in events]
            events_json.sort(key=lambda x: x["timestamp"])

            # Fetch all events from the index
            response = _elastic_request("GET", "https://localhost:9200/bbot_test_events/_search?size=100")
            response_json = json.loads(response.read())
            db_events = [hit["_source"] for hit in response_json["hits"]["hits"]]

            # make sure we have the same number of events
            assert len(events_json) == len(db_events)

            for db_event in db_events:
                assert isinstance(db_event["timestamp"], float)
                assert isinstance(db_event["inserted_at"], float)

            # Convert to Pydantic objects and dump them
            db_events_pydantic = [Event(**e).model_dump(exclude_none=True) for e in db_events]
            db_events_pydantic.sort(key=lambda x: x["timestamp"])

            # Find the main event with type DNS_NAME and data blacklanternsecurity.com
            main_event = next(
                (
                    e
                    for e in db_events_pydantic
                    if e.get("type") == "DNS_NAME" and e.get("data") == "blacklanternsecurity.com"
                ),
                None,
            )
            assert main_event is not None, "Main event with type DNS_NAME and data blacklanternsecurity.com not found"

            # Ensure it has the reverse_host attribute
            expected_reverse_host = "blacklanternsecurity.com"[::-1]
            assert main_event.get("reverse_host") == expected_reverse_host, (
                f"reverse_host attribute is not correct, expected {expected_reverse_host}"
            )

            # Events don't match exactly because the elastic ones have reverse_host and inserted_at
            assert events_json != db_events_pydantic
            for db_event in db_events_pydantic:
                db_event.pop("reverse_host", None)
                db_event.pop("inserted_at", None)
                db_event.pop("archived", None)
            # They should match after removing reverse_host
            assert events_json == db_events_pydantic, "Events do not match"

        finally:
            # Clean up: Delete all documents in the index
            try:
                _elastic_request("DELETE", "https://localhost:9200/bbot_test_events?ignore=400,404")
            except URLError:
                pass
            self.log.verbose("Deleted documents from index")
            process = await asyncio.create_subprocess_exec(
                "docker", "stop", "bbot-test-elastic", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
