from neo4j import GraphDatabase
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
        self.driver = GraphDatabase.driver(uri=uri, auth=(username, password))

    def insert_event(self, event):
        self.insert_events([event])

    def insert_events(self, events):
        # event_nodes = dict()
        # event_list = []

        for event in events:
            event_json = event.json(mode="graph")

            source_id = event_json.get("source", "")
            if not source_id:
                log.warning(f"Skipping event without source: {event}")
                continue
            event_type = event_json.pop("type")
            relation_type = event_json.pop("module", "TARGET")
            dest_id = event_json.get("id", "")
            # timestamp = datetime.fromtimestamp(event_json.pop("timestamp"))
            datetime.fromtimestamp(event_json.pop("timestamp"))

            self.make_node(event_type, event_json)
            if source_id is not dest_id:
                self.make_relationship(event_type, source_id, relation_type, dest_id)
                # "{event} {event_json.get(str(event), "")}"
            # log.warning(exec_statement)

    def make_node(self, event_type, event_json):
        exec_statement = f"MERGE (:{event_type} " + "{"
        for event in event_json:
            if "scope_distance" in str(event) or "tags" in str(event):
                myString = f"{event}: {event_json.get(str(event))},"
            else:
                myString = f'{event}: "{event_json.get(str(event))}",'
            # log.warning(myString)
            exec_statement += myString
        exec_statement = exec_statement[:-1]
        exec_statement += "})"

        # log.warning(exec_statement)

        session = self.driver.session()
        session.run(exec_statement)

    def make_relationship(self, event_type, source_id, relation_type, dest_id):
        source_type = source_id.split(":")[0]
        # _source_id = source_id.split(":")[1]
        dest_type = dest_id.split(":")[0]
        # _dest_id = dest_id.split(":")[1]
        # log.warning(f"source_type: {source_type} - source_id: {_source_id} - relation_type: {relation_type} - dest_id: {dest_id}")

        exec_statement = (
            f'MATCH (source:{source_type} {{id: "{source_id}"}}) '
            f'MATCH (target:{dest_type} {{id: "{dest_id}"}}) '
            f"MERGE (source)-[r:{relation_type}]->(target) "
            f"RETURN COUNT(r) AS total"
        )

        # query = ("MATCH (source: $source_type, id: $source_id) "
        #          "MATCH (target: $dest_type, id: $dest_id) "
        #          "MERGE (source)-[r: $relation_type]->(target) "
        #          "RETURN COUNT(r) AS total")

        # log.warning(exec_statement)

        session = self.driver.session()
        # result = session.run(query,
        #                      source_type=source_type,
        #                      source_id=source_id,
        #                      dest_type=dest_type,
        #                      dest_id=dest_id,
        #                      relation_type=relation_type)

        result = session.run(exec_statement)
        # exec_result = session.execute_read(exec_statement, "RETURN COUNT(r) AS total")

        # log.warning(f"Result: {result}")

        record = result.single()
        # log.warning(f"Total Relationships: {record['total']}")

        if record["total"] == 0:
            self.make_relationship(event_type, source_id, relation_type, dest_id)
