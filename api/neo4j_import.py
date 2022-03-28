#!/usr/bin/env python3

import json
import py2neo
import argparse


# docker run --rm -p 7687:7687 -p 7474:7474 --env NEO4J_AUTH=neo4j/bbotislife neo4j

_graph = py2neo.Graph(uri="bolt://localhost:7687", auth=("neo4j", "bbotislife"))


parser = argparse.ArgumentParser(description="")
parser.add_argument("-i", "--ingest", required=True, help="json")
options = parser.parse_args()


events = dict()
event_list = []

with open(options.ingest) as f:
    for line in f:
        event = json.loads(line)
        eventNode = py2neo.Node(event.get("type"), **event)
        eventNode.__primarylabel__ = event.get("type")
        eventNode.__primarykey__ = "id"
        events[event.get("id")] = eventNode
        event_list.append(eventNode)

subgraph = list(events.values())[0]
for destEvent in event_list:
    _id = destEvent.get("id")
    if not _id.endswith(":TARGET"):
        module = destEvent.get("module")
        try:
            sourceEvent = events[destEvent.get("source")]
        except KeyError:
            subgraph = subgraph | destEvent
            continue
        relation = py2neo.Relationship(sourceEvent, module, destEvent)
        subgraph = subgraph | relation

_graph.merge(subgraph)
