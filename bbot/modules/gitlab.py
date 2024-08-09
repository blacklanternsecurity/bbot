from bbot.modules.base import BaseModule


class gitlab(BaseModule):
    watched_events = ["HTTP_RESPONSE", "TECHNOLOGY", "SOCIAL"]
    produced_events = ["TECHNOLOGY", "SOCIAL", "CODE_REPOSITORY", "FINDING"]
    flags = ["active", "safe", "code-enum"]
    meta = {
        "description": "Detect GitLab instances and query them for repositories",
        "created_date": "2024-03-11",
        "author": "@TheTechromancer",
    }
    options = {"api_key": ""}
    options_desc = {"api_key": "Gitlab access token"}

    scope_distance_modifier = 2

    async def setup(self):
        self.headers = {}
        self.api_key = self.config.get("api_key", "")
        if self.api_key:
            self.headers.update({"Authorization": f"Bearer {self.api_key}"})
        return True

    async def filter_event(self, event):
        # only accept out-of-scope SOCIAL events
        if event.type == "HTTP_RESPONSE":
            if event.scope_distance > self.scan.scope_search_distance:
                return False, "event is out of scope distance"
        elif event.type == "TECHNOLOGY":
            if not event.data["technology"].lower().startswith("gitlab"):
                return False, "technology is not gitlab"
            if not self.helpers.is_ip(event.host) and self.helpers.tldextract(event.host).domain == "gitlab":
                return False, "gitlab instance is not self-hosted"
        elif event.type == "SOCIAL":
            if event.data["platform"] != "gitlab":
                return False, "platform is not gitlab"
        return True

    async def handle_event(self, event):
        if event.type == "HTTP_RESPONSE":
            await self.handle_http_response(event)
        elif event.type == "TECHNOLOGY":
            await self.handle_technology(event)
        elif event.type == "SOCIAL":
            await self.handle_social(event)

    async def handle_http_response(self, event):
        # identify gitlab instances from HTTP responses
        # HTTP_RESPONSE --> TECHNOLOGY
        # HTTP_RESPONSE --> FINDING
        headers = event.data.get("header", {})
        if "x_gitlab_meta" in headers:
            url = event.parsed_url._replace(path="/").geturl()
            await self.emit_event(
                {"host": str(event.host), "technology": "GitLab", "url": url},
                "TECHNOLOGY",
                parent=event,
                context=f"{{module}} detected {{event.type}}: GitLab at {url}",
            )
            description = f"GitLab server at {event.host}"
            await self.emit_event(
                {"host": str(event.host), "description": description},
                "FINDING",
                parent=event,
                context=f"{{module}} detected {{event.type}}: {description}",
            )

    async def handle_technology(self, event):
        # retrieve gitlab groups from gitlab instances
        # TECHNOLOGY --> SOCIAL
        # TECHNOLOGY --> URL
        # TECHNOLOGY --> CODE_REPOSITORY
        base_url = self.get_base_url(event)
        projects_url = self.helpers.urljoin(base_url, "api/v4/projects?simple=true")
        await self.handle_projects_url(projects_url, event)
        groups_url = self.helpers.urljoin(base_url, "api/v4/groups?simple=true")
        await self.handle_groups_url(groups_url, event)

    async def handle_social(self, event):
        # retrieve repositories from gitlab user
        # SOCIAL --> CODE_REPOSITORY
        # SOCIAL --> SOCIAL
        username = event.data.get("profile_name", "")
        if not username:
            return
        base_url = self.get_base_url(event)
        urls = [
            # group
            self.helpers.urljoin(base_url, f"api/v4/users/{username}/projects?simple=true"),
            # user
            self.helpers.urljoin(base_url, f"api/v4/groups/{username}/projects?simple=true"),
        ]
        for url in urls:
            await self.handle_projects_url(url, event)

    async def handle_projects_url(self, projects_url, event):
        for project in await self.gitlab_json_request(projects_url):
            project_url = project.get("web_url", "")
            if project_url:
                code_event = self.make_event({"url": project_url}, "CODE_REPOSITORY", tags="git", parent=event)
                await self.emit_event(
                    code_event, context=f"{{module}} enumerated projects and found {{event.type}} at {project_url}"
                )
            namespace = project.get("namespace", {})
            if namespace:
                await self.handle_namespace(namespace, event)

    async def handle_groups_url(self, groups_url, event):
        for group in await self.gitlab_json_request(groups_url):
            await self.handle_namespace(group, event)

    async def gitlab_json_request(self, url):
        response = await self.helpers.request(url, headers=self.headers)
        if response is not None:
            try:
                json = response.json()
            except Exception:
                return []
            if json and isinstance(json, list):
                return json
        return []

    async def handle_namespace(self, namespace, event):
        namespace_name = namespace.get("path", "")
        namespace_url = namespace.get("web_url", "")
        namespace_path = namespace.get("full_path", "")
        if namespace_name and namespace_url and namespace_path:
            namespace_url = self.helpers.parse_url(namespace_url)._replace(path=f"/{namespace_path}").geturl()
            social_event = self.make_event(
                {"platform": "gitlab", "profile_name": namespace_path, "url": namespace_url},
                "SOCIAL",
                parent=event,
            )
            await self.emit_event(
                social_event,
                context=f'{{module}} found GitLab namespace ({{event.type}}) "{namespace_name}" at {namespace_url}',
            )

    def get_base_url(self, event):
        base_url = event.data.get("url", "")
        if not base_url:
            base_url = f"https://{event.host}"
        return self.helpers.urlparse(base_url)._replace(path="/").geturl()
