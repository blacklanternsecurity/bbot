from bbot.db.neo4j import Neo4j

from bbot.modules.output.base import BaseOutputModule


class neo4j(BaseOutputModule):
    """
    docker run --rm -p 7687:7687 -p 7474:7474 --env NEO4J_AUTH=neo4j/bbotislife neo4j
    """

    watched_events = ["*"]
    meta = {"description": "Output to Neo4j"}
    options = {"uri": "bolt://localhost:7687", "username": "neo4j", "password": "bbotislife"}
    options_desc = {
        "uri": "Neo4j server + port",
        "username": "Neo4j username",
        "password": "Neo4j password",
    }
    deps_pip = ["py2neo"]
    batch_size = 50

    def setup(self):
        try:
            self.neo4j = Neo4j(
                uri=self.config.get("uri", self.options["uri"]),
                username=self.config.get("username", self.options["username"]),
                password=self.config.get("password", self.options["password"]),
            )
            self.neo4j.insert_event(self.scan.root_event)
        except Exception as e:
            self.warning(f"Error setting up Neo4j: {e}")
            return False
        return True

    def handle_event(self, event):
        self.neo4j.insert_event(event)

    def handle_batch(self, *events):
        self.neo4j.insert_events(events)
