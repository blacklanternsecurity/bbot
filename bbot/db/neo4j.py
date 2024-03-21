from neo4j import GraphDatabase
import logging
from datetime import datetime


log = logging.getLogger("bbot.db.neo4j")

# uncomment this to enable neo4j debugging
# logging.basicConfig(level=logging.DEBUG, format="%(message)s")


class Neo4j:
    """
    # start Neo4j in the background with docker
    docker run -d -p 7687:7687 -p 7474:7474 -v "$(pwd)/neo4j/:/data/" -e NEO4J_AUTH=neo4j/bbotislife neo4j

    # view all running docker containers
    > docker ps

    # view all docker containers
    > docker ps -a

    # stop a docker container
    > docker stop <CONTAINER_ID>

    # remove a docker container
    > docker remove <CONTAINER_ID>

    # start a stopped container
    > docker start <CONTAINER_ID>
    """

    queue_list = []

    def __init__(self, uri="bolt://localhost:7687", username="neo4j", password="bbotislife"):
        self.driver = GraphDatabase.driver(uri=uri, auth=(username, password))

        # # UN-COMMENT TO FORCE NEO4J TO ERASE ALL PREVIOUS RECORDS
        # # The Neo4j Query Statement that will remove previous Neo4j records
        # neo4j_statement = "MATCH (n) DETACH DELETE (n) " "RETURN COUNT(n) as total"
        # session = self.driver.session()
        # result = session.run(neo4j_statement)
        # record = result.single()
        # log.info(f"Deleted {record['total']} Neo4j Records from previous scans")
        # session.close()

    def insert_event(self, event):
        self.insert_events([event])

    def insert_events(self, events):
        self.session = self.driver.session()
        for event in events:
            event_json = event.json(mode="graph")

            source_id = event_json.get("source", "")
            if not source_id:
                log.warning(f"Skipping event without source: {event}")
                continue
            event_type = event_json.pop("type")
            relation_type = event_json.pop("module", "TARGET")
            dest_id = event_json.get("id", "")
            datetime.fromtimestamp(event_json.pop("timestamp"))

            # Prompt Neo4j to create a Node (Entity)
            self.make_node(event_type, event_json)
            if source_id is not dest_id:
                # Prompt Neo4j to create a relationship between this node and its Source Node
                self.make_relationship(event_type, source_id, relation_type, dest_id)
        self.session.close()

    def make_node(self, event_type, event_json):
        # Create the Exec Statement. Example:
        # MERGE (:SCAN {id: "SCAN:<id>",data: "liquid_irene (SCAN:<id>)",scope_distance: 0,scan: "SCAN:6<id>",
        #    timestamp: "1710815413.899545",source: "SCAN:<id>",tags: ['in-scope'],module_sequence: "TARGET"})
        exec_statement = f"MERGE (:{event_type} " + "{"
        for item in event_json:
            if "scope_distance" in str(item) or "tags" in str(item):
                myString = f"{item}: {event_json.get(str(item))},"
            else:
                myString = f'{item}: "{event_json.get(str(item))}",'
            if "data" in str(item) and "{" in str(event_json.get(str(item))):
                myString = f'{item}: "{self.parse_data(str(event_json.get(str(item))))}",'
            exec_statement += myString
        exec_statement = exec_statement[:-1]
        exec_statement += "})"

        # Instantiate Driver Session and Run Exec_Statement (aka - send to Neo4j to graph)
        self.session.run(exec_statement)

    def make_relationship(self, event_type, source_id, relation_type, dest_id):
        # Revisit Relationships that didn't succeed earlier because the Source Event wasn't created yet
        if self.queue_list:
            index = 0
            for pending_event in self.queue_list:
                for key, exec_statement in pending_event.items():
                    result = self.session.run(exec_statement)
                    record = result.single()

                    # If the neo4j Exec_Statement returns Source Count of Zero
                    if "0" in {str(record["total"])}:
                        index = index + 1
                        continue  # Try Again

                    # Else there is an existing source that we can relate to
                    else:
                        del self.queue_list[index]

        # Creating Types from ID's provided
        source_type = source_id.split(":")[0]
        dest_type = dest_id.split(":")[0]

        # The Neo4j Query Statement Template to be passed
        relationship_statement = (
            f'MATCH (source:{source_type} {{id: "{source_id}"}}) '
            f'MATCH (target:{dest_type} {{id: "{dest_id}"}}) '
            f"MERGE (source)-[r:{relation_type}]->(target) "
            f"RETURN COUNT(source) as total"
        )

        result = self.session.run(relationship_statement)
        record = result.single()

        # If there are no existing Source_Types, then we cannot relate.
        # We must queue this relationship to run later after the Source Node has been created
        if "0" in {str(record["total"])}:
            # Try again later after source event has been created
            pending_event = {source_id: relationship_statement}
            self.queue_list.append(pending_event)

    def parse_data(self, event_json_str):
        _string = "".join(str(event_json_str))
        return _string.replace('"', '\\"')

    async def cleanup(self):
        self.driver.close()
