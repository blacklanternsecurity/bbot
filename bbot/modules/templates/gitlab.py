from bbot.modules.base import BaseModule


class GitLabBaseModule(BaseModule):
    """Common functionality for interacting with GitLab instances.

    This template is intended to be inherited by two concrete modules:
    1. ``gitlab_com``   – Handles public SaaS instances (gitlab.com / gitlab.org).
    2. ``gitlab_onprem`` – Handles self-hosted, on-premises GitLab servers.

    Both child modules share identical behaviour when talking to the GitLab
    REST API; they only differ in which events they are willing to accept.
    """

    # domains owned by GitLab
    saas_domains = ["gitlab.com", "gitlab.org"]

    async def setup(self):
        if self.options.get("api_key") is not None:
            await self.require_api_key()
        return True

    async def handle_social(self, event):
        """Enumerate projects belonging to a user or group profile."""
        username = event.data.get("profile_name", "")
        if not username:
            return
        base_url = self.get_base_url(event)
        urls = [
            # User-owned projects
            self.helpers.urljoin(base_url, f"api/v4/users/{username}/projects?simple=true"),
            # Group-owned projects
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
                    code_event,
                    context=f"{{module}} enumerated projects and found {{event.type}} at {project_url}",
                )
            namespace = project.get("namespace", {})
            if namespace:
                await self.handle_namespace(namespace, event)

    async def handle_groups_url(self, groups_url, event):
        for group in await self.gitlab_json_request(groups_url):
            await self.handle_namespace(group, event)

    async def gitlab_json_request(self, url):
        """Helper that performs an HTTP request and safely returns JSON list."""
        response = await self.api_request(url)
        if response is not None:
            try:
                json_data = response.json()
            except Exception:
                return []
            if json_data and isinstance(json_data, list):
                return json_data
        return []

    async def handle_namespace(self, namespace, event):
        namespace_name = namespace.get("path", "")
        namespace_url = namespace.get("web_url", "")
        namespace_path = namespace.get("full_path", "")

        if not (namespace_name and namespace_url and namespace_path):
            return

        namespace_url = self.helpers.parse_url(namespace_url)._replace(path=f"/{namespace_path}").geturl()

        social_event = self.make_event(
            {
                "platform": "gitlab",
                "profile_name": namespace_path,
                "url": namespace_url,
            },
            "SOCIAL",
            parent=event,
        )
        await self.emit_event(
            social_event,
            context=f'{{module}} found GitLab namespace ({{event.type}}) "{namespace_name}" at {namespace_url}',
        )

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------
    def get_base_url(self, event):
        base_url = event.data.get("url", "")
        if not base_url:
            base_url = f"https://{event.host}"
        return self.helpers.urlparse(base_url)._replace(path="/").geturl()
