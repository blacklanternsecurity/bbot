from .webhook import webhook
from bbot.core.config.models import BaseModuleConfig, Field


class Elastic(webhook):
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
            sensitive=True,
        )
        username: str = Field("elastic", description="Elastic username", sensitive=True)
        password: str = Field("bbotislife", description="Elastic password", sensitive=True)
        timeout: int = Field(10, description="HTTP timeout")

    async def cleanup(self):
        # refresh the index
        doc_regex = self.helpers.re.compile(r"/[^/]+$")
        refresh_url = doc_regex.sub("/_refresh", self.url)
        await self.helpers.request(refresh_url, auth=self.auth)
