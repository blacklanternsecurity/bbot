from .base import BaseModule
from bbot.db.neo4j import Neo4j


class neo4j(BaseModule):
    """
    docker run --rm -p 7687:7687 -p 7474:7474 --env NEO4J_AUTH=neo4j/bbotislife neo4j
    """

    watched_events = ["*"]
    options = {"uri": "bolt://localhost:7687", "username": "neo4j", "password": "bbotislife"}
    options_desc = {
        "uri": "Neo4j server + port",
        "username": "Neo4j username",
        "password": "Neo4j password",
    }
    accept_dupes = True

    def setup(self):

        try:
            self.neo4j = Neo4j(
                uri=self.config.get("uri", self.options["uri"]),
                username=self.config.get("username", self.options["username"]),
                password=self.config.get("password", self.options["password"]),
            )
            self.neo4j.insert_event(self.scan.root_event)
        except Exception as e:
            self.error(f"Error setting up Neo4j: {e}")
            import traceback

            self.debug(traceback.format_exc())
            self.set_error_state()
        return True

    def handle_event(self, event):
        self.neo4j.insert_event(event)

    def handle_batch(self, *events):
        """
        Todo: Fix error with larger batch sizes
            File "/home/bls/Downloads/code/bbot/bbot/modules/base.py", line 90, in catch
                return callback(*args, **kwargs)
              File "/home/bls/Downloads/code/bbot/bbot/modules/neo4j.py", line 42, in handle_batch
                self.neo4j.insert_events(events)
              File "/home/bls/Downloads/code/bbot/bbot/db/neo4j.py", line 44, in insert_events
                self.graph.merge(subgraph)
              File "/home/bls/.cache/pypoetry/virtualenvs/bbot-yxGMlPK5-py3.10/lib/python3.10/site-packages/py2neo/database.py", line 678, in merge
                self.update(lambda tx: tx.merge(subgraph, label, *property_keys))
              File "/home/bls/.cache/pypoetry/virtualenvs/bbot-yxGMlPK5-py3.10/lib/python3.10/site-packages/py2neo/database.py", line 445, in update
                self._update(cypher, timeout=timeout)
              File "/home/bls/.cache/pypoetry/virtualenvs/bbot-yxGMlPK5-py3.10/lib/python3.10/site-packages/py2neo/database.py", line 470, in _update
                value = f(tx)
              File "/home/bls/.cache/pypoetry/virtualenvs/bbot-yxGMlPK5-py3.10/lib/python3.10/site-packages/py2neo/database.py", line 678, in <lambda>
                self.update(lambda tx: tx.merge(subgraph, label, *property_keys))
              File "/home/bls/.cache/pypoetry/virtualenvs/bbot-yxGMlPK5-py3.10/lib/python3.10/site-packages/py2neo/database.py", line 1132, in merge
                merge(self, primary_label, primary_key)
              File "/home/bls/.cache/pypoetry/virtualenvs/bbot-yxGMlPK5-py3.10/lib/python3.10/site-packages/py2neo/data.py", line 320, in __db_merge__
                raise UniquenessError("Found %d matching nodes for primary label %r and primary "
            py2neo.data.UniquenessError: Found 2 matching nodes for primary label 'data' and primary key 'id' with labels {'DNS_NAME'} but merging requires no more than one
        """
        self.neo4j.insert_events(events)
