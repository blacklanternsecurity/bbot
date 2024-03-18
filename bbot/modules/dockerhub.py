from bbot.modules.base import BaseModule


class dockerhub(BaseModule):
    watched_events = ["SOCIAL", "ORG_STUB"]
    produced_events = ["SOCIAL", "CODE_REPOSITORY", "URL_UNVERIFIED"]
    flags = ["active", "safe"]
    meta = {"description": "Search for docker repositories of discovered orgs/usernames"}

    scope_distance_modifier = 2

    async def filter_event(self, event):
        if event.type == "SOCIAL":
            if event.data["platform"] != "docker":
                return False, "platform is not docker"
        return True

    async def handle_event(self, event):
        if event.type == "ORG_STUB":
            await self.emit_social(event)
        elif event.type == "SOCIAL":
            await self.handle_social(event)

    async def emit_social(self, event):
        profile_name = event.data
        url = "https://hub.docker.com/u/" + profile_name.lower()
        await self.emit_event({"platform": "docker", "url": url, "profile_name": profile_name}, "SOCIAL", source=event)

    async def handle_social(self, event):
        username = event.data.get("profile_name", "")
        if not username:
            return
        await self.emit_event(
            "https://hub.docker.com/v2/users/" + username, "URL_UNVERIFIED", source=event, tags="httpx-safe"
        )
        self.verbose(f"Searching for docker images belonging to {username}")
        repos = await self.get_repos(username)
        for repo in repos:
            await self.emit_event({"url": repo}, "CODE_REPOSITORY", tags="docker", source=event)

    async def get_repos(self, username):
        repos = []
        url = f"https://hub.docker.com/v2/repositories/{username}?page_size=25&page=" + "{page}"
        agen = self.helpers.api_page_iter(url, json=False)
        try:
            async for r in agen:
                if r is None:
                    break
                status_code = getattr(r, "status_code", 0)
                if status_code != 200:
                    break
                try:
                    j = r.json()
                except Exception as e:
                    self.warning(f"Failed to decode JSON for {r.url} (HTTP status: {status_code}): {e}")
                    break
                if not j:
                    break
                for item in j.get("results", []):
                    image_name = item.get("name", "")
                    namespace = item.get("namespace", "")
                    if image_name and namespace:
                        repos.append("https://hub.docker.com/r/" + namespace + "/" + image_name)
        finally:
            agen.aclose()
        return repos
