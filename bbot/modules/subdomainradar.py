import time
import asyncio

from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey


class SubdomainRadar(subdomain_enum_apikey):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {
        "description": "Query the Subdomain API for subdomains",
        "created_date": "2022-07-08",
        "author": "@TheTechromancer",
        "auth_required": True,
    }
    options = {"api_key": "", "group": "fast", "timeout": 120}
    options_desc = {"api_key": "SubDomainRadar.io API key", "group": "", "timeout": "Timeout in seconds"}

    base_url = "https://api.subdomainradar.io"
    group_choices = ("fast", "medium", "deep")

    async def setup(self):
        self.group = self.config.get("group", "fast").strip().lower()
        if self.group not in self.group_choices:
            return False, f'Invalid group: "{self.group}", please choose from {",".join(self.group_choices)}'
        success, reason = await self.require_api_key()
        if not success:
            return success, reason
        # convert groups to enumerators
        enumerators = {}
        response = await self.api_request(f"{self.base_url}/enumerators/groups")
        status_code = getattr(response, "status_code", 0)
        if status_code != 200:
            return False, f"Failed to get enumerators: (HTTP status code: {status_code})"
        else:
            try:
                j = response.json()
            except Exception:
                return False, f"Failed to get enumerators: failed to parse response as JSON"
            for group in j:
                group_name = group.get("name", "").strip().lower()
                if group_name:
                    group_enumerators = []
                    for enumerator in group.get("enumerators", []):
                        enumerator_name = enumerator.get("display_name", "")
                        if enumerator_name:
                            group_enumerators.append(enumerator_name)
                    if group_enumerators:
                        enumerators[group_name] = group_enumerators

        self.enumerators = enumerators.get(self.group, [])
        if not self.enumerators:
            return False, f'No enumerators found for group: "{self.group}" ({self.enumerators})'

        self.enum_tasks = {}
        self.poll_task = asyncio.create_task(self.task_poll_loop())

        return True

    def prepare_api_request(self, url, kwargs):
        if self.api_key:
            kwargs["headers"] = {"Authorization": f"Bearer {self.api_key}"}
        return url, kwargs

    async def ping(self):
        url = f"{self.base_url}/profile"
        response = await self.api_request(url)
        assert getattr(response, "status_code", 0) == 200

    async def handle_event(self, event):
        query = self.make_query(event)
        # start enumeration task
        url = f"{self.base_url}/enumerate"
        response = await self.api_request(url, json={"domains": [query], "enumerators": self.enumerators})
        try:
            j = response.json()
        except Exception:
            self.warning(f"Failed to parse response as JSON: {getattr(response, 'text', '')}")
            return
        task_id = j.get("tasks", {}).get(query, "")
        if not task_id:
            self.warning(f"Failed to initiate enumeration task for {query}")
            return
        self.enum_tasks[query] = (task_id, time.time(), event)
        self.debug(f"Started enumeration task for {query}; task id: {task_id}")

    async def task_poll_loop(self):
        # async with self._task_counter.count(f"{self.name}.task_poll_loop()"):
        while 1:
            for query, (task_id, start_time, event) in list(self.enum_tasks.items()):
                url = f"{self.base_url}/tasks/{task_id}"
                response = await self.api_request(url)
                if getattr(response, "status_code", 0) == 200:
                    finished = await self.parse_response(response, query, event)
                    if finished:
                        self.enum_tasks.pop(query)
                        continue
                # if scan is finishing, consider timeout
                if self.scan.status == "FINISHING":
                    if start_time + self.timeout < time.time():
                        self.enum_tasks.pop(query)
                        self.info(f"Enumeration task for {query} timed out")

            if self.scan.status == "FINISHING" and not self.enum_tasks:
                break
            await self.helpers.sleep(5)

    async def parse_response(self, response, query, event):
        j = response.json()
        status = j.get("status", "")
        if status.lower() == "completed":
            for subdomain in j.get("subdomains", []):
                hostname = subdomain.get("subdomain", "")
                if hostname and hostname.endswith(f".{query}") and not hostname == event.data:
                    await self.emit_event(
                        hostname,
                        "DNS_NAME",
                        event,
                        abort_if=self.abort_if,
                        context=f'{{module}} searched SubDomainRadar.io API for "{query}" and found {{event.type}}: {{event.data}}',
                    )
            return True
        return False

    async def finish(self):
        await self.poll_task
