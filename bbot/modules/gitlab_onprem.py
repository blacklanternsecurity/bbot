from bbot.modules.templates.gitlab import GitLabBaseModule


class gitlab_onprem(GitLabBaseModule):
    watched_events = ["HTTP_RESPONSE", "TECHNOLOGY", "SOCIAL"]
    produced_events = [
        "TECHNOLOGY",
        "SOCIAL",
        "CODE_REPOSITORY",
        "FINDING",
    ]
    flags = ["active", "safe", "code-enum"]
    meta = {
        "description": "Detect self-hosted GitLab instances and query them for repositories",
        "created_date": "2024-03-11",
        "author": "@TheTechromancer",
    }

    # Optional GitLab access token (only required for gitlab.com, but still
    # supported for on-prem installations that expose private projects).
    options = {"api_key": ""}
    options_desc = {"api_key": "GitLab access token (for self-hosted instances only)"}

    # Allow accepting events slightly beyond configured max distance so we can
    # discover repos on neighbouring infrastructure.
    scope_distance_modifier = 2

    async def handle_event(self, event):
        if event.type == "HTTP_RESPONSE":
            await self.handle_http_response(event)
        elif event.type == "TECHNOLOGY":
            await self.handle_technology(event)
        elif event.type == "SOCIAL":
            await self.handle_social(event)

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
            _, domain = self.helpers.split_domain(event.host)
            if domain in self.saas_domains:
                return False, "gitlab instance is not self-hosted"
        return True

    async def handle_http_response(self, event):
        """Identify GitLab servers from HTTP responses."""
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
        """Enumerate projects & groups once we know a host is GitLab."""
        base_url = self.get_base_url(event)

        # Projects owned by the authenticated user (or public projects if no
        # authentication).
        projects_url = self.helpers.urljoin(base_url, "api/v4/projects?simple=true")
        await self.handle_projects_url(projects_url, event)

        # Group enumeration.
        groups_url = self.helpers.urljoin(base_url, "api/v4/groups?simple=true")
        await self.handle_groups_url(groups_url, event)
