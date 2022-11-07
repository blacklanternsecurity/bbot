import py2neo
import logging
from datetime import datetime

log = logging.getLogger("bbot.db.neo4j")

# uncomment this to enable neo4j debugging
# logging.basicConfig(level=logging.DEBUG, format="%(message)s")


class Neo4j:
    """
    docker run --rm -p 7687:7687 -p 7474:7474 --env NEO4J_AUTH=neo4j/bbotislife neo4j
    """

    def __init__(self, uri="bolt://localhost:7687", username="neo4j", password="bbotislife"):
        self.graph = py2neo.Graph(uri=uri, auth=(username, password))

    def insert_event(self, event):
        self.insert_events([event])

    def insert_events(self, events):
        event_nodes = dict()
        event_list = []

        for event in events:
            event_json = event.json(mode="graph")
            source_id = event_json.get("source", "")
            if not source_id:
                log.warning(f"Skipping event without source: {event}")
                continue
            event_node = self.make_node(event_json)
            event_nodes[event.id] = event_node
            event_list.append(event_node)

        if event_nodes:
            subgraph = list(event_nodes.values())[0]
            for dest_event in event_list:
                module = dest_event.pop("module", "TARGET")
                source_id = dest_event["source"]
                source_type = source_id.split(":")[0]
                try:
                    source_event = event_nodes[source_id]
                except KeyError:
                    source_event = self.make_node({"type": source_type, "id": source_id})
                timestamp = datetime.fromtimestamp(dest_event.pop("timestamp"))
                relation = py2neo.Relationship(source_event, module, dest_event, timestamp=timestamp)
                subgraph = subgraph | relation

            self.graph.merge(subgraph)

    @staticmethod
    def make_node(event):
        event = dict(event)
        event_type = event.pop("type")
        event_node = py2neo.Node(event_type, **event)
        event_node.__primarylabel__ = event_type
        event_node.__primarykey__ = "id"
        return event_node
