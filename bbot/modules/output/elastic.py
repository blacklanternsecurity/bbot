from .http import HTTP


class Elastic(HTTP):
    watched_events = ["*"]
    metadata = {
        "description": "Send scan results to Elasticsearch",
        "created_date": "2022-11-21",
        "author": "@TheTechromancer",
    }
    options = {
        "url": "",
        "username": "elastic",
        "password": "changeme",
        "timeout": 10,
    }
    options_desc = {
        "url": "Elastic URL (e.g. https://localhost:9200/<your_index>/_doc)",
        "username": "Elastic username",
        "password": "Elastic password",
        "timeout": "HTTP timeout",
    }
