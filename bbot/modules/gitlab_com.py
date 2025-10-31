from bbot.modules.templates.gitlab import GitLabBaseModule


class gitlab_com(GitLabBaseModule):
    watched_events = ["SOCIAL"]
    produced_events = [
        "CODE_REPOSITORY",
    ]
    flags = ["active", "safe", "code-enum"]
    meta = {
        "description": "Enumerate GitLab SaaS (gitlab.com/org) for projects and groups",
        "created_date": "2024-03-11",
        "author": "@TheTechromancer",
    }

    options = {"api_key": ""}
    options_desc = {"api_key": "GitLab access token (for gitlab.com/org only)"}

    # This is needed because we are consuming SOCIAL events, which aren't in scope
    scope_distance_modifier = 2

    async def handle_event(self, event):
        await self.handle_social(event)

    async def filter_event(self, event):
        if event.data["platform"] != "gitlab":
            return False, "platform is not gitlab"
        _, domain = self.helpers.split_domain(event.host)
        if domain not in self.saas_domains:
            return False, "gitlab instance is not gitlab.com/org"
        return True
