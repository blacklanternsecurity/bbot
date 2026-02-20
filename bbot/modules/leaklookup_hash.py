from bbot.modules.leaklookup import leaklookup


class leaklookup_hash(leaklookup):
    watched_events = ["HASHED_PASSWORD"]
    produced_events = ["PASSWORD"]
    flags = ["passive", "safe", "email-enum"]
    meta = {
        "description": "Query leak-lookup.com for plaintext passwords using hashes",
        "created_date": "2026-02-19",
        "author": "@carlospolop",
        "auth_required": True,
    }

