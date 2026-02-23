from bbot.modules.leaklookup import leaklookup


class leaklookup_dns(leaklookup):
    watched_events = ["DNS_NAME"]
    produced_events = ["EMAIL_ADDRESS", "FINDING", "HASHED_PASSWORD", "PASSWORD", "USERNAME"]
    flags = ["passive", "safe", "email-enum"]
    meta = {
        "description": "Query leak-lookup.com for leaked credentials using DNS names",
        "created_date": "2026-02-19",
        "author": "@carlospolop",
        "auth_required": True,
    }
