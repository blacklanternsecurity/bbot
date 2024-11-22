import time
import httpx
import asyncio

from .base import ModuleTestBase


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

        # Connect to Elasticsearch with retry logic
        async with httpx.AsyncClient(verify=False) as client:
            while True:
                try:
                    # Attempt a simple operation to confirm the connection
                    response = await client.get("https://localhost:9200/_cat/health", auth=("elastic", "bbotislife"))
                    response.raise_for_status()
                    break
                except Exception as e:
                    self.log.verbose(f"Connection failed: {e}. Retrying...")
                    time.sleep(0.5)

            # Ensure the index is empty
            await client.delete(f"https://localhost:9200/bbot_test_events", auth=("elastic", "bbotislife"))

    async def check(self, module_test, events):
        try:
            from bbot.models.pydantic import Event

            events_json = [e.json() for e in events]
            events_json.sort(key=lambda x: x["timestamp"])

            # Connect to Elasticsearch
            async with httpx.AsyncClient(verify=False) as client:

                # Fetch all events from the index
                response = await client.get(
                    f"https://localhost:9200/bbot_test_events/_search?size=100", auth=("elastic", "bbotislife")
                )
                response_json = response.json()
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
                assert (
                    main_event is not None
                ), "Main event with type DNS_NAME and data blacklanternsecurity.com not found"

                # Ensure it has the reverse_host attribute
                expected_reverse_host = "blacklanternsecurity.com"[::-1]
                assert (
                    main_event.get("reverse_host") == expected_reverse_host
                ), f"reverse_host attribute is not correct, expected {expected_reverse_host}"

                # Events don't match exactly because the elastic ones have reverse_host and inserted_at
                assert events_json != db_events_pydantic
                for db_event in db_events_pydantic:
                    db_event.pop("reverse_host")
                    db_event.pop("inserted_at")
                # They should match after removing reverse_host
                assert events_json == db_events_pydantic, "Events do not match"

        finally:
            # Clean up: Delete all documents in the index
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.delete(
                    f"https://localhost:9200/bbot_test_events",
                    auth=("elastic", "bbotislife"),
                    params={"ignore": "400,404"},
                )
                self.log.verbose(f"Deleted documents from index")
            await asyncio.create_subprocess_exec(
                "docker", "stop", "bbot-test-elastic", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
