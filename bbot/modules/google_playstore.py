from bbot.modules.base import BaseModule


class google_playstore(BaseModule):
    watched_events = ["ORG_STUB", "CODE_REPOSITORY"]
    produced_events = ["MOBILE_APP"]
    flags = ["passive", "safe", "code-enum"]
    meta = {
        "description": "Search for android applications on play.google.com",
        "created_date": "2024-10-08",
        "author": "@domwhewell-sage",
    }

    base_url = "https://play.google.com"

    async def filter_event(self, event):
        if event.type == "CODE_REPOSITORY":
            if "android" not in event.tags:
                return False, "event is not an android repository"
        return True

    async def handle_event(self, event):
        if event.type == "CODE_REPOSITORY":
            await self.handle_url(event)
        elif event.type == "ORG_STUB":
            await self.handle_org_stub(event)

    async def handle_url(self, event):
        repo_url = event.data.get("url")
        app_id = repo_url.split("id=")[1].split("&")[0]
        await self.emit_event(
            {"id": app_id, "url": repo_url},
            "MOBILE_APP",
            tags="android",
            parent=event,
            context=f'{{module}} extracted the mobile app name "{app_id}"  from: {repo_url}',
        )

    async def handle_org_stub(self, event):
        org_name = event.data
        self.verbose(f"Searching for any android applications for {org_name}")
        for apk_name in await self.query(org_name):
            valid_apk = await self.validate_apk(apk_name)
            if valid_apk:
                self.verbose(f"Got {apk_name} from playstore")
                await self.emit_event(
                    {"id": apk_name, "url": f"{self.base_url}/store/apps/details?id={apk_name}"},
                    "MOBILE_APP",
                    tags="android",
                    parent=event,
                    context=f'{{module}} searched play.google.com for apps belonging to "{org_name}" and found "{apk_name}" to be in scope',
                )
            else:
                self.debug(f"Got {apk_name} from playstore app details does not contain any in-scope URLs or Emails")

    async def query(self, query):
        app_links = []
        url = f"{self.base_url}/store/search?q={self.helpers.quote(query)}&c=apps"
        r = await self.helpers.request(url)
        if r is None:
            return app_links
        status_code = getattr(r, "status_code", 0)
        try:
            html = self.helpers.beautifulsoup(r.content, "html.parser")
        except Exception as e:
            self.warning(f"Failed to parse html response from {r.url} (HTTP status: {status_code}): {e}")
            return app_links
        links = html.find_all("a", href=True)
        app_links = [a["href"].split("id=")[1].split("&")[0] for a in links if "/store/apps/details?id=" in a["href"]]
        return app_links

    async def validate_apk(self, apk_name):
        in_scope = False
        url = f"{self.base_url}/store/apps/details?id={apk_name}"
        r = await self.helpers.request(url)
        if r is None:
            return in_scope
        status_code = getattr(r, "status_code", 0)
        try:
            html = self.helpers.beautifulsoup(r.content, "html.parser")
        except Exception as e:
            self.warning(f"Failed to parse html response from {r.url} (HTTP status: {status_code}): {e}")
            return in_scope
        # The developer meta tag usually contains the developer's URL
        developer_meta = html.find("meta", attrs={"name": "appstore:developer_url"})
        developer_url = developer_meta["content"] if developer_meta else None
        if self.scan.in_scope(developer_url):
            in_scope = True
        # If the developers URL is left blank then a support email is usually provided
        links = html.find_all("a", href=True)
        emails = [a["href"].split("mailto:")[1] for a in links if "mailto:" in a["href"]]
        for email in emails:
            if self.scan.in_scope(email):
                in_scope = True
                break
        return in_scope
