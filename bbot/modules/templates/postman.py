from bbot.modules.base import BaseModule


class postman(BaseModule):
    """
    A template module for use of the GitHub API
    Inherited by several other github modules.
    """

    base_url = "https://www.postman.com/_api"
    api_url = "https://api.getpostman.com"
    html_url = "https://www.postman.com"
    ping_url = f"{api_url}/me"

    headers = {
        "Content-Type": "application/json",
        "X-App-Version": "11.27.4-250109-2338",
        "X-Entity-Team-Id": "0",
        "Origin": "https://www.postman.com",
        "Referer": "https://www.postman.com/search?q=&scope=public&type=all",
    }
    auth_required = True

    async def setup(self):
        await super().setup()
        self.headers = {}
        api_keys = set()
        modules_config = self.scan.config.get("modules", {})
        postman_modules = [m for m in modules_config if str(m).startswith("postman")]
        for module_name in postman_modules:
            module_config = modules_config.get(module_name, {})
            api_key = module_config.get("api_key", "")
            if isinstance(api_key, str):
                api_key = [api_key]
            for key in api_key:
                key = key.strip()
                if key:
                    api_keys.add(key)
        if not api_keys:
            if self.auth_required:
                return None, "No API key set"
        self.api_key = api_keys
        if self.api_key:
            try:
                await self.ping()
                self.hugesuccess("API is ready")
                return True
            except Exception as e:
                self.trace()
                return None, f"Error with API ({str(e).strip()})"
        return True

    def prepare_api_request(self, url, kwargs):
        if self.api_key:
            kwargs["headers"]["X-Api-Key"] = self.api_key
        return url, kwargs

    async def get_workspace_id(self, repo_url):
        workspace_id = ""
        profile = repo_url.split("/")[-2]
        name = repo_url.split("/")[-1]
        url = f"{self.base_url}/ws/proxy"
        json = {
            "service": "workspaces",
            "method": "GET",
            "path": f"/workspaces?handle={profile}&slug={name}",
        }
        r = await self.helpers.request(url, method="POST", json=json, headers=self.headers)
        if r is None:
            return workspace_id
        status_code = getattr(r, "status_code", 0)
        try:
            json = r.json()
        except Exception as e:
            self.warning(f"Failed to decode JSON for {r.url} (HTTP status: {status_code}): {e}")
            return workspace_id
        data = json.get("data", [])
        if len(data) == 1:
            workspace_id = data[0]["id"]
        return workspace_id

    async def request_workspace(self, id):
        data = {"workspace": {}, "environments": [], "collections": []}
        workspace = await self.get_workspace(id)
        if workspace:
            # Main Workspace
            name = workspace["name"]
            data["workspace"] = workspace

            # Workspace global variables
            self.verbose(f"Searching globals for workspace {name}")
            globals = await self.get_globals(id)
            data["environments"].append(globals)

            # Workspace Environments
            workspace_environments = workspace.get("environments", [])
            if workspace_environments:
                self.verbose(f"Searching environments for workspace {name}")
                for _ in workspace_environments:
                    environment_id = _["uid"]
                    environment = await self.get_environment(environment_id)
                    data["environments"].append(environment)

            # Workspace Collections
            workspace_collections = workspace.get("collections", [])
            if workspace_collections:
                self.verbose(f"Searching collections for workspace {name}")
                for _ in workspace_collections:
                    collection_id = _["uid"]
                    collection = await self.get_collection(collection_id)
                    data["collections"].append(collection)
        return data

    async def get_workspace(self, workspace_id):
        workspace = {}
        workspace_url = f"{self.api_url}/workspaces/{workspace_id}"
        r = await self.api_request(workspace_url)
        if r is None:
            return workspace
        status_code = getattr(r, "status_code", 0)
        try:
            json = r.json()
        except Exception as e:
            self.warning(f"Failed to decode JSON for {r.url} (HTTP status: {status_code}): {e}")
            return workspace
        workspace = json.get("workspace", {})
        return workspace

    async def get_globals(self, workspace_id):
        globals = {}
        globals_url = f"{self.base_url}/workspace/{workspace_id}/globals"
        r = await self.helpers.request(globals_url, headers=self.headers)
        if r is None:
            return globals
        status_code = getattr(r, "status_code", 0)
        try:
            json = r.json()
        except Exception as e:
            self.warning(f"Failed to decode JSON for {r.url} (HTTP status: {status_code}): {e}")
            return globals
        globals = json.get("data", {})
        return globals

    async def get_environment(self, environment_id):
        environment = {}
        environment_url = f"{self.api_url}/environments/{environment_id}"
        r = await self.api_request(environment_url)
        if r is None:
            return environment
        status_code = getattr(r, "status_code", 0)
        try:
            json = r.json()
        except Exception as e:
            self.warning(f"Failed to decode JSON for {r.url} (HTTP status: {status_code}): {e}")
            return environment
        environment = json.get("environment", {})
        return environment

    async def get_collection(self, collection_id):
        collection = {}
        collection_url = f"{self.api_url}/collections/{collection_id}"
        r = await self.api_request(collection_url)
        if r is None:
            return collection
        status_code = getattr(r, "status_code", 0)
        try:
            json = r.json()
        except Exception as e:
            self.warning(f"Failed to decode JSON for {r.url} (HTTP status: {status_code}): {e}")
            return collection
        collection = json.get("collection", {})
        return collection

    async def validate_workspace(self, workspace, environments, collections):
        name = workspace.get("name", "")
        full_wks = str([workspace, environments, collections])
        in_scope_hosts = await self.scan.extract_in_scope_hostnames(full_wks)
        if in_scope_hosts:
            self.verbose(
                f'Found in-scope hostname(s): "{in_scope_hosts}" in workspace {name}, it appears to be in-scope'
            )
            return True
        return False
