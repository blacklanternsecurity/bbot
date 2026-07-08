import json
from pathlib import Path
from bbot.modules.base import BaseModule
from bbot.core.config.models import BaseModuleConfig, Field


class graphql_introspection(BaseModule):
    watched_events = ["URL"]
    produced_events = ["FINDING"]
    flags = ["safe", "active", "web"]
    meta = {
        "description": "Perform GraphQL introspection on a target",
        "created_date": "2025-07-01",
        "author": "@mukesh-dream11",
    }

    class Config(BaseModuleConfig):
        graphql_endpoint_urls: list[str] = Field(
            ["/", "/graphql", "/v1/graphql"], description="List of GraphQL endpoint to suffix to the target URL"
        )
        output_folder: str = Field("", description="Folder to save the GraphQL schemas to")

    async def setup(self):
        output_folder = self.config.get("output_folder", "")
        if output_folder:
            self.output_dir = Path(output_folder) / "graphql-schemas"
        else:
            self.output_dir = self.scan.home / "graphql-schemas"
        return True

    async def filter_event(self, event):
        # Dedup by the base URL
        base_url = event.parsed_url._replace(path="/", query="", fragment="").geturl()
        return hash(base_url)

    async def handle_event(self, event):
        base_url = event.parsed_url._replace(path="/", query="", fragment="").geturl().rstrip("/")
        for endpoint_url in self.config.get("graphql_endpoint_urls", []):
            url = f"{base_url}{endpoint_url}"
            request_args = {
                "url": url,
                "method": "POST",
                "json": {
                    "query": """\
query IntrospectionQuery {
    __schema {
        queryType {
            name
        }
        mutationType {
            name
        }
        types {
            name
            kind
            description
            fields(includeDeprecated: true) {
                name
                description
                type {
                    ... TypeRef
                }
                isDeprecated
                deprecationReason
            }
            interfaces {
                ... TypeRef
            }
            possibleTypes {
                ... TypeRef
            }
            enumValues(includeDeprecated: true) {
                name
                description
                isDeprecated
                deprecationReason
            }
            ofType {
                ... TypeRef
            }
        }
    }
}

fragment TypeRef on __Type {
    kind
    name
    ofType {
    kind
    name
    ofType {
        kind
        name
        ofType {
        kind
        name
        ofType {
            kind
            name
            ofType {
            kind
            name
            ofType {
                kind
                name
                ofType {
                kind
                name
                }
            }
            }
        }
        }
    }
    }
}"""
                },
            }
            response = await self.helpers.request(**request_args)
            if not response or response.status_code != 200:
                self.debug(
                    f"Failed to get GraphQL schema for {url} "
                    f"{f'(status code {response.status_code})' if response else ''}"
                )
                continue
            try:
                response_json = response.json()
            except json.JSONDecodeError:
                self.debug(f"Failed to parse JSON for {url}")
                continue
            if response_json.get("data", {}).get("__schema", {}).get("types", []):
                self.helpers.mkdir(self.output_dir)
                filename = f"schema-{self.helpers.tagify(url)}.json"
                filename = self.output_dir / filename
                with open(filename, "w") as f:
                    json.dump(response_json, f)
                relative_path = str(filename.relative_to(self.scan.home))
                await self.emit_event(
                    {
                        "name": "GraphQL Schema",
                        "url": url,
                        "description": f"GraphQL Schema at {url}",
                        "path": relative_path,
                        "severity": "INFO",
                        "confidence": "CONFIRMED",
                    },
                    "FINDING",
                    event,
                    context=f"{{module}} found GraphQL schema at {url}",
                )
                # return, because we only want to find one schema per target
                return
