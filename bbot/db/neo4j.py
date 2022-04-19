import py2neo
import logging

log = logging.getLogger("bbot.db.neo4j")

# docker run --rm -p 7687:7687 -p 7474:7474 --env NEO4J_AUTH=neo4j/bbotislife neo4j


class Neo4j:
    def __init__(self, uri="bolt://localhost:7687", username="neo4j", password="bbotislife"):
        self.graph = py2neo.Graph(uri=uri, auth=(username, password))

    def insert_event(self, event):
        event_json = event.json

        try:
            source_id = event_json.pop("source")
        except KeyError:
            log.warning(f"Skipping event without source: {event_json}")
            return
        source_type = source_id.split(":")[-1]
        source_node = self.make_node({"type": source_type, "id": source_id})

        module = event_json.pop("module", "TARGET")
        event_node = self.make_node(event_json)

        relationship = py2neo.Relationship(source_node, module, event_node)
        self.graph.merge(relationship)

    def insert_events(self, events):
        event_nodes = dict()
        event_list = []

        for event in events:
            event_node = self.make_node(event.json)
            if event.id in event_nodes:
                event_node = event_nodes[event.id] | event_node
            event_node = self.make_node(event.json)
            event_nodes[event.id] = event_node
            event_list.append(event_node)

        subgraph = list(event_nodes.values())[0]
        for dest_event in event_list:
            module = dest_event.pop("module", "TARGET")
            try:
                source_id = dest_event.pop("source")
            except KeyError:
                log.warning(f"Skipping event without source: {dest_event}")
                continue
            source_type = source_id.split(":")[-1]
            try:
                source_event = event_nodes[source_id]
            except KeyError:
                source_event = self.make_node({"type": source_type, "id": source_id})
            relation = py2neo.Relationship(source_event, module, dest_event)
            subgraph = subgraph | relation

        self.graph.merge(subgraph)

    @staticmethod
    def make_node(event):
        event = dict(event)
        if "scan_id" in event:
            event["scan_ids"] = [event.pop("scan_id")]
        event_type = event.pop("type")
        event_node = py2neo.Node(event_type, **event)
        event_node.__primarylabel__ = "data"
        event_node.__primarykey__ = "id"
        return event_node
