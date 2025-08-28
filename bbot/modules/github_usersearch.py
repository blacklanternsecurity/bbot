from bbot.modules.templates.github import github
from bbot.modules.templates.subdomain_enum import subdomain_enum


class github_usersearch(github, subdomain_enum):
    watched_events = ["DNS_NAME"]
    produced_events = ["SOCIAL", "EMAIL_ADDRESS"]
    flags = ["passive", "safe", "code-enum"]
    meta = {
        "description": "Query Github's API for users with emails matching in scope domains that may not be discoverable by listing members of the organization.",
        "created_date": "2025-05-10",
        "author": "@domwhewell-sage",
        "auth_required": True,
    }
    options = {"api_key": ""}
    options_desc = {"api_key": "Github token"}

    async def handle_event(self, event):
        self.verbose("Searching for users with emails matching in scope domains")
        query = self.make_query(event)
        users = await self.query_users(query)
        for user, email in users:
            user_url = f"https://github.com/{user}"
            event_data = {"platform": "github", "profile_name": user, "url": user_url}
            user_event = self.make_event(event_data, "SOCIAL", tags="github-org-member", parent=event)
            if user_event:
                await self.emit_event(
                    user_event,
                    context=f"{{module}} searched for users with {{DNS_NAME}} in the profile and discovered {{event.type}}: {user_url}",
                )
            if email:
                await self.emit_event(
                    email,
                    "EMAIL_ADDRESS",
                    parent=event,
                    context=f"{{module}} found an {{event.type}} on the github profile {user_url}: {{event.data}}",
                )

    async def query_users(self, query):
        users = []
        graphql_query = f"""query search_users {{
            search(query: "{query}", type: USER, first: 100, after: "{{NEXT_KEY}}") {{
                userCount
                pageInfo {{
                    hasNextPage
                    endCursor
                }}
                edges {{
                    node {{
                        ... on User {{
                          login
                          # bio Commented out as user can add arbritrary domains to their bio
                          email # Email is verified by github
                          websiteUrl # Website is not verified by github
                        }}
                    }}
                }}
            }}
        }}"""
        async for data in self.github_graphql_request(graphql_query, "search"):
            if data:
                user_count = data.get("userCount", 0)
                self.verbose(f"Found {user_count} users with the query {query}, verifying if they are in-scope...")
                edges = data.get("edges", [])
                for node in edges:
                    user = node.get("node", {})
                    in_scope_hosts = await self.scan.extract_in_scope_hostnames(str(user))
                    if in_scope_hosts:
                        login = user.get("login", "")
                        email = user.get("email", None)
                        self.verbose(
                            f'Found in-scope hostname(s): "{in_scope_hosts}" in the profile https://github.com/{login}, the profile appears to be in-scope'
                        )
                        users.append((login, email))
        return users
