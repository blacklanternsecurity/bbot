from neo4j import AsyncGraphDatabase

from bbot.modules.output.base import BaseOutputModule


class neo4j(BaseOutputModule):
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

    watched_events = ["*"]
    meta = {"description": "Output to Neo4j", "created_date": "2022-04-07", "author": "@TheTechromancer"}
    options = {"uri": "bolt://localhost:7687", "username": "neo4j", "password": "bbotislife"}
    options_desc = {
        "uri": "Neo4j server + port",
        "username": "Neo4j username",
        "password": "Neo4j password",
    }
    deps_pip = ["neo4j"]
    _preserve_graph = True

    async def setup(self):
        try:
            self.driver = AsyncGraphDatabase.driver(
                uri=self.config.get("uri", self.options["uri"]),
                auth=(
                    self.config.get("username", self.options["username"]),
                    self.config.get("password", self.options["password"]),
                ),
            )
            self.session = self.driver.session()
            await self.handle_event(self.scan.root_event)
        except Exception as e:
            return False, f"Error setting up Neo4j: {e}"
        return True

    async def handle_event(self, event):
        # create events
        src_id = await self.merge_event(event.get_source(), id_only=True)
        dst_id = await self.merge_event(event)
        # create relationship
        cypher = f"""
        MATCH (a) WHERE id(a) = $src_id
        MATCH (b) WHERE id(b) = $dst_id
        MERGE (a)-[_:{event.module}]->(b)
        SET _.timestamp = $timestamp"""
        await self.session.run(cypher, src_id=src_id, dst_id=dst_id, timestamp=event.timestamp)

    async def merge_event(self, event, id_only=False):
        if id_only:
            eventdata = {"type": event.type, "id": event.id}
        else:
            eventdata = event.json(mode="graph")
            # we pop the timestamp because it belongs on the relationship
            eventdata.pop("timestamp")
        cypher = f"""MERGE (_:{event.type} {{ id: $eventdata['id'] }})
        SET _ += $eventdata
        RETURN id(_)"""
        # insert event
        result = await self.session.run(cypher, eventdata=eventdata)
        # get Neo4j id
        return (await result.single()).get("id(_)")

    async def cleanup(self):
        await self.session.close()
        await self.driver.close()
