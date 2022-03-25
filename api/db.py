import pymongo

client = pymongo.MongoClient(username="bbot", password="bbotislife")


def get_collection():
    db = client.bbot
    return db["events"]


def insert_event(event):
    events = get_collection()
    _id = event.pop("id")
    source = event.pop("source")
    query = {"$set": event, "$addToSet": {"sources": source}}
    result = events.update_one({"_id": _id}, query, upsert=True)
    return result.raw_result
