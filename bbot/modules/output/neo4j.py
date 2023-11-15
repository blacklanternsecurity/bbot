from bbot.db.neo4j import Neo4j
from bbot.modules.output.base import BaseOutputModule


class neo4j(BaseOutputModule):
    """
    docker run -p 7687:7687 -p 7474:7474 -v "$(pwd)/data/:/data/" -e NEO4J_AUTH=neo4j/bbotislife neo4j
    """

    watched_events = ["*"]
    meta = {"description": "Output to Neo4j"}
    options = {"uri": "bolt://localhost:7687", "username": "neo4j", "password": "bbotislife"}
    options_desc = {
        "uri": "Neo4j server + port",
        "username": "Neo4j username",
        "password": "Neo4j password",
    }
    deps_pip = ["git+https://github.com/blacklanternsecurity/py2neo"]
    _batch_size = 50
    _preserve_graph = True

    async def setup(self):
        try:
            self.neo4j = await self.scan.run_in_executor(
                Neo4j,
                uri=self.config.get("uri", self.options["uri"]),
                username=self.config.get("username", self.options["username"]),
                password=self.config.get("password", self.options["password"]),
            )
            await self.scan.run_in_executor(self.neo4j.insert_event, self.scan.root_event)
        except Exception as e:
            self.warning(f"Error setting up Neo4j: {e}")
            return False
        return True

    async def handle_event(self, event):
        await self.scan.run_in_executor(self.neo4j.insert_event, event)

    async def handle_batch(self, *events):
        await self.scan.run_in_executor(self.neo4j.insert_events, events)
