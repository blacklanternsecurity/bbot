from .http import HTTP
from pydantic import Field
from bbot.core.config.models import BaseModuleConfig


class Elastic(HTTP):
    """
    docker run -d -p 9200:9200 --name=bbot-elastic --v "$(pwd)/elastic_data:/usr/share/elasticsearch/data" -e ELASTIC_PASSWORD=bbotislife -m 1GB docker.elastic.co/elasticsearch/elasticsearch:8.16.0
    """

    watched_events = ["*"]
    meta = {
        "description": "Send scan results to Elasticsearch",
        "created_date": "2022-11-21",
        "author": "@TheTechromancer",
    }

    class Config(BaseModuleConfig):
        url: str = Field(
            "https://localhost:9200/bbot_events/_doc",
            description="Elastic URL (e.g. https://localhost:9200/<your_index>/_doc)",
        )
        username: str = Field("elastic", description="Elastic username")
        password: str = Field("bbotislife", description="Elastic password")
        timeout: int = Field(10, description="HTTP timeout")

    async def cleanup(self):
        # refresh the index
        doc_regex = self.helpers.re.compile(r"/[^/]+$")
        refresh_url = doc_regex.sub("/_refresh", self.url)
        await self.helpers.request(refresh_url, auth=self.auth)
