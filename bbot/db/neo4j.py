from neo4j import GraphDatabase
import logging


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
        # The Neo4j Query Statement that will remove previous Neo4j records
        neo4j_statement = "MATCH (n) DETACH DELETE (n) " "RETURN COUNT(n) as total"

        # Setup Neo4j Driver Session and Send neo4j_statement
        session = self.driver.session()
        result = session.run(neo4j_statement)
        record = result.single()
        log.warning(f"Deleted {record['total']} Neo4j Records from previous scans")

    def insert_event(self, event):
        self.insert_events([event])

    def insert_events(self, events):
        for event in events:
            event_json = event.json(mode="graph")

            source_id = event_json.get("source", "")
            if not source_id:
                log.warning(f"Skipping event without source: {event}")
                continue
            event_type = event_json.pop("type")
            relation_type = event_json.pop("module", "TARGET")
            dest_id = event_json.get("id", "")

            # Prompt Neo4j to create a Node (Entity)
            self.make_node(event_type, event_json)
            if source_id is not dest_id:
                # Prompt Neo4j to create a relationship between this node and its Source Node
                self.make_relationship(event_type, source_id, relation_type, dest_id)

    def make_node(self, event_type, event_json):
        # Create the Exec Statement. Example:
        # MERGE (:SCAN {id: "SCAN:<id>",data: "liquid_irene (SCAN:<id>)",scope_distance: 0,scan: "SCAN:6<id>",
        #    timestamp: "1710815413.899545",source: "SCAN:<id>",tags: ['in-scope'],module_sequence: "TARGET"})
        exec_statement = f"MERGE (:{event_type} " + "{"
        for event in event_json:
            if "scope_distance" in str(event) or "tags" in str(event):
                myString = f"{event}: {event_json.get(str(event))},"
            else:
                myString = f'{event}: "{event_json.get(str(event))}",'
            exec_statement += myString
        exec_statement = exec_statement[:-1]
        exec_statement += "})"

        # Instantiate Driver Session and Run Exec_Statement (aka - send to Neo4j to graph)
        # log.warning(exec_statement)
        session = self.driver.session()
        session.run(exec_statement)

    def make_relationship(self, event_type, source_id, relation_type, dest_id):
        # Initiate the Neo4j Driver Session
        session = self.driver.session()

        # Revisit Relationships that didn't succeed earlier because the Source Event wasn't created yet
        if self.queue_list:
            index = 0
            for pending_event in self.queue_list:
                for key, exec_statement in pending_event.items():
                    # log.debug(f"{key} : {exec_statement}")
                    result = session.run(exec_statement)
                    record = result.single()

                    # If the neo4j Exec_Statement returns Source Count of Zero
                    if "0" in {str(record["total"])}:
                        index = index + 1
                        continue  # Try Again

                    # Else there is an existing source that we can relate to
                    else:
                        # log.warning(self.queue_list[index])
                        del self.queue_list[index]

        # Creating Types from ID's provided
        source_type = source_id.split(":")[0]
        dest_type = dest_id.split(":")[0]
        # log.warning(f"source_type: {source_type} - source_id: {_source_id} - relation_type: {relation_type} - dest_id: {dest_id}")

        # The Neo4j Query Statement Template to be passed
        relationship_statement = (
            f'MATCH (source:{source_type} {{id: "{source_id}"}}) '
            f'MATCH (target:{dest_type} {{id: "{dest_id}"}}) '
            f"MERGE (source)-[r:{relation_type}]->(target) "
            f"RETURN COUNT(source) as total"
        )

        # log.warning(exec_statement)
        result = session.run(relationship_statement)
        record = result.single()

        # If there are no existing Source_Types, then we cannot relate.
        # We must queue this relationship to run later after the Source Node has been created
        # log.warning(f"Count for {source_type}: {record['total']}")
        if "0" in {str(record["total"])}:
            # try again later after source event has been created
            pending_event = {source_id: relationship_statement}
            self.queue_list.append(pending_event)
