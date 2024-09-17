import json
import logging
from contextlib import suppress
from neo4j import AsyncGraphDatabase

from bbot.modules.output.base import BaseOutputModule


# silence annoying neo4j logger
logging.getLogger("neo4j").setLevel(logging.CRITICAL)


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
    _batch_size = 500
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
            await self.session.run("Match () Return 1 Limit 1")
        except Exception as e:
            return False, f"Error setting up Neo4j: {e}"
        return True

    async def handle_batch(self, *all_events):
        # group events by type, since cypher doesn't allow dynamic labels
        events_by_type = {}
        parents_by_type = {}
        relationships = []
        for event in all_events:
            parent = event.get_parent()
            try:
                events_by_type[event.type].append(event)
            except KeyError:
                events_by_type[event.type] = [event]
            try:
                parents_by_type[parent.type].append(parent)
            except KeyError:
                parents_by_type[parent.type] = [parent]

            module = str(event.module)
            timestamp = event.timestamp
            relationships.append((parent, module, timestamp, event))

        all_ids = {}
        for event_type, events in events_by_type.items():
            self.debug(f"{len(events):,} events of type {event_type}")
            all_ids.update(await self.merge_events(events, event_type))
        for event_type, parents in parents_by_type.items():
            self.debug(f"{len(parents):,} parents of type {event_type}")
            all_ids.update(await self.merge_events(parents, event_type, id_only=True))

        rel_ids = []
        for parent, module, timestamp, event in relationships:
            try:
                src_id = all_ids[parent.id]
                dst_id = all_ids[event.id]
            except KeyError as e:
                self.error(f'Error "{e}" correlating {parent.id}:{parent.data} --> {event.id}:{event.data}')
                continue
            rel_ids.append((src_id, module, timestamp, dst_id))

        await self.merge_relationships(rel_ids)

    async def merge_events(self, events, event_type, id_only=False):
        if id_only:
            insert_data = [{"data": str(e.data), "type": e.type, "id": e.id} for e in events]
        else:
            insert_data = []
            for e in events:
                event_json = e.json(mode="graph")
                # we pop the timestamp because it belongs on the relationship
                event_json.pop("timestamp")
                # nested data types aren't supported in neo4j
                for key in ("dns_children", "discovery_path"):
                    if key in event_json:
                        event_json[key] = json.dumps(event_json[key])
                insert_data.append(event_json)

        cypher = f"""UNWIND $events AS event
        MERGE (_:{event_type} {{ id: event.id }})
        SET _ += properties(event)
        RETURN event.data as event_data, event.id as event_id, elementId(_) as neo4j_id"""
        neo4j_ids = {}
        # insert events
        try:
            results = await self.session.run(cypher, events=insert_data)
            # get Neo4j ids
            for result in await results.data():
                event_id = result["event_id"]
                neo4j_id = result["neo4j_id"]
                neo4j_ids[event_id] = neo4j_id
        except Exception as e:
            self.error(f"Error inserting Neo4j nodes (label:{event_type}): {e}")
            self.trace(insert_data)
            self.trace(cypher)
        return neo4j_ids

    async def merge_relationships(self, relationships):
        rels_by_module = {}
        # group by module
        for src_id, module, timestamp, dst_id in relationships:
            data = {"src_id": src_id, "timestamp": timestamp, "dst_id": dst_id}
            try:
                rels_by_module[module].append(data)
            except KeyError:
                rels_by_module[module] = [data]

        for module, rels in rels_by_module.items():
            self.debug(f"{len(rels):,} relationships of type {module}")
            cypher = f"""
            UNWIND $rels AS rel
            MATCH (a) WHERE elementId(a) = rel.src_id
            MATCH (b) WHERE elementId(b) = rel.dst_id
            MERGE (a)-[_:{module}]->(b)
            SET _.timestamp = rel.timestamp"""
            try:
                await self.session.run(cypher, rels=rels)
            except Exception as e:
                self.error(f"Error inserting Neo4j relationship (label:{module}): {e}")
                self.trace(cypher)

    async def cleanup(self):
        with suppress(Exception):
            await self.session.close()
        with suppress(Exception):
            await self.driver.close()
