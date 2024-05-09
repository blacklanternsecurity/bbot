from bbot.modules.base import BaseModule


class dockerhub(BaseModule):
    watched_events = ["SOCIAL", "ORG_STUB"]
    produced_events = ["SOCIAL", "CODE_REPOSITORY", "URL_UNVERIFIED"]
    flags = ["passive", "safe"]
    meta = {"description": "Search for docker repositories of discovered orgs/usernames"}

    site_url = "https://hub.docker.com"
    api_url = f"{site_url}/v2"

    scope_distance_modifier = 2

    async def filter_event(self, event):
        if event.type == "SOCIAL":
            if event.data["platform"] != "docker":
                return False, "platform is not docker"
        return True

    async def handle_event(self, event):
        if event.type == "ORG_STUB":
            await self.handle_org_stub(event)
        elif event.type == "SOCIAL":
            await self.handle_social(event)

    async def handle_org_stub(self, event):
        profile_name = event.data
        # docker usernames are case sensitive, so if there are capitalizations we also try a lowercase variation
        profiles_to_check = set([profile_name, profile_name.lower()])
        for p in profiles_to_check:
            api_url = f"{self.api_url}/users/{p}"
            api_result = await self.helpers.request(api_url, follow_redirects=True)
            status_code = getattr(api_result, "status_code", 0)
            if status_code == 200:
                site_url = f"{self.site_url}/u/{p}"
                # emit social event
                await self.emit_event(
                    {"platform": "docker", "url": site_url, "profile_name": p}, "SOCIAL", source=event
                )

    async def handle_social(self, event):
        username = event.data.get("profile_name", "")
        if not username:
            return
        # emit API endpoint to be visited by httpx (for url/email extraction, etc.)
        await self.emit_event(f"{self.api_url}/users/{username}", "URL_UNVERIFIED", source=event, tags="httpx-safe")
        self.verbose(f"Searching for docker images belonging to {username}")
        repos = await self.get_repos(username)
        for repo in repos:
            await self.emit_event({"url": repo}, "CODE_REPOSITORY", tags="docker", source=event)

    async def get_repos(self, username):
        repos = []
        url = f"{self.api_url}/repositories/{username}?page_size=25&page=" + "{page}"
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
