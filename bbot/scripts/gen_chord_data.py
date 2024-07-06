# This script generates the dataset for the chord graph in the documentation
#  showing relationships between BBOT modules and their consumed/produced event types

import json
from pathlib import Path

from bbot.core.modules import MODULE_LOADER


def gen_chord_data():

    preloaded_mods = sorted(MODULE_LOADER.preloaded().items(), key=lambda x: x[0])

    entity_lookup_table = {}
    rels = []
    entities = {}
    entity_counter = 1

    def add_entity(entity, parent_id):
        if entity not in entity_lookup_table:
            nonlocal entity_counter
            e_id = entity_counter
            entity_counter += 1
            entity_lookup_table[entity] = e_id
            entity_lookup_table[e_id] = entity
            entities[e_id] = {"id": e_id, "name": entity, "parent": parent_id, "consumes": [], "produces": []}
        return entity_lookup_table[entity]

    # create entities for all the modules and event types
    for module, preloaded in preloaded_mods:
        watched = [e for e in preloaded["watched_events"] if e != "*"]
        produced = [e for e in preloaded["produced_events"] if e != "*"]
        if watched or produced:
            m_id = add_entity(module, 99999999)
            for event_type in watched:
                e_id = add_entity(event_type, 88888888)
                entities[m_id]["consumes"].append(e_id)
                entities[e_id]["consumes"].append(m_id)
            for event_type in produced:
                e_id = add_entity(event_type, 88888888)
                entities[m_id]["produces"].append(e_id)
                entities[e_id]["produces"].append(m_id)

    def add_rel(incoming, outgoing, t):
        if incoming == "*" or outgoing == "*":
            return
        i_id = entity_lookup_table[incoming]
        o_id = entity_lookup_table[outgoing]
        rels.append({"source": i_id, "target": o_id, "type": t})

    # create all the module <--> event type relationships
    for module, preloaded in preloaded_mods:
        for event_type in preloaded["watched_events"]:
            add_rel(module, event_type, "consumes")
        for event_type in preloaded["produced_events"]:
            add_rel(event_type, module, "produces")

    # write them to JSON files
    data_dir = Path(__file__).parent.parent.parent / "docs" / "data" / "chord_graph"
    data_dir.mkdir(parents=True, exist_ok=True)
    entity_file = data_dir / "entities.json"
    rels_file = data_dir / "rels.json"

    entities = [
        {"id": 77777777, "name": "root"},
        {"id": 99999999, "name": "module", "parent": 77777777},
        {"id": 88888888, "name": "event_type", "parent": 77777777},
    ] + sorted(entities.values(), key=lambda x: x["name"])

    with open(entity_file, "w") as f:
        json.dump(entities, f, indent=4)

    with open(rels_file, "w") as f:
        json.dump(rels, f, indent=4)
