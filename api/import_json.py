#!/usr/bin/env python3

import json
import argparse

from db import get_collection, insert_event

# docker run --rm -e MONGO_INITDB_ROOT_USERNAME=bbot -e MONGO_INITDB_ROOT_PASSWORD=bbotislife mongo

parser = argparse.ArgumentParser(description="BBOT FastAPI")
parser.add_argument("-p", "--password", default="bbotislife", help="MongoDB root password")
parser.add_argument("-i", "--import-json", help="Import file containing event JSON")
options = parser.parse_args()

if options.import_json:
    events = get_collection()
    # read events from JSON
    with open(options.import_json) as f:
        for line in f:
            event = json.loads(line)
            result = insert_event(event)
            print(result)
