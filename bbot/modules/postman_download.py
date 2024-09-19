import zipfile
import json
from pathlib import Path
from bbot.modules.templates.postman import postman


class postman_download(postman):
    watched_events = ["CODE_REPOSITORY"]
    produced_events = ["FILESYSTEM"]
    flags = ["passive", "subdomain-enum", "safe", "code-enum"]
    meta = {
        "description": "Download workspaces, collections, requests from Postman",
        "created_date": "2024-09-07",
        "author": "@domwhewell-sage",
    }
    options = {"output_folder": "", "api_key": ""}
    options_desc = {"output_folder": "Folder to download postman workspaces to", "api_key": "Postman API Key"}
    scope_distance_modifier = 2

    async def setup(self):
        self.api_key = self.config.get("api_key", "")
        self.authorization_headers = {"X-Api-Key": self.api_key}

        output_folder = self.config.get("output_folder")
        if output_folder:
            self.output_dir = Path(output_folder) / "postman_workspaces"
        else:
            self.output_dir = self.scan.home / "postman_workspaces"
        self.helpers.mkdir(self.output_dir)
        return await self.require_api_key()

    async def ping(self):
        url = f"{self.api_url}/me"
        response = await self.helpers.request(url, headers=self.authorization_headers)
        assert getattr(response, "status_code", 0) == 200, response.text

    async def filter_event(self, event):
        if event.type == "CODE_REPOSITORY":
            if "postman" not in event.tags:
                return False, "event is not a postman workspace"
        return True

    async def handle_event(self, event):
        repo_url = event.data.get("url")
        workspace_id = await self.get_workspace_id(repo_url)
        if workspace_id:
            self.verbose(f"Found workspace ID {workspace_id} for {repo_url}")
            workspace_path = await self.download_workspace(workspace_id)
            if workspace_path:
                self.verbose(f"Downloaded workspace from {repo_url} to {workspace_path}")
                codebase_event = self.make_event(
                    {"path": str(workspace_path)}, "FILESYSTEM", tags=["postman", "workspace"], parent=event
                )
                await self.emit_event(
                    codebase_event,
                    context=f"{{module}} downloaded postman workspace at {repo_url} to {{event.type}}: {workspace_path}",
                )

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

    async def download_workspace(self, id):
        zip_path = None
        workspace = await self.get_workspace(id)
        if workspace:
            # Create a folder for the workspace
            name = workspace["name"]
            folder = self.output_dir / name
            self.helpers.mkdir(folder)
            zip_path = folder / f"{id}.zip"

            # Main Workspace
            self.add_json_to_zip(zip_path, workspace, f"{name}.postman_workspace.json")

            # Workspace global variables
            self.verbose(f"Downloading globals for workspace {name}")
            globals = await self.get_globals(id)
            globals_id = globals["id"]
            self.add_json_to_zip(zip_path, globals, f"{globals_id}.postman_environment.json")

            # Workspace Environments
            workspace_environments = workspace.get("environments", [])
            if workspace_environments:
                self.verbose(f"Downloading environments for workspace {name}")
                for _ in workspace_environments:
                    environment_id = _["uid"]
                    environment = await self.get_environment(environment_id)
                    self.add_json_to_zip(zip_path, environment, f"{environment_id}.postman_environment.json")

            # Workspace Collections
            workspace_collections = workspace.get("collections", [])
            if workspace_collections:
                self.verbose(f"Downloading collections for workspace {name}")
                for _ in workspace_collections:
                    collection_id = _["uid"]
                    collection = await self.get_collection(collection_id)
                    self.add_json_to_zip(zip_path, collection, f"{collection_id}.postman_collection.json")
        return zip_path

    async def get_workspace(self, workspace_id):
        workspace = {}
        workspace_url = f"{self.api_url}/workspaces/{workspace_id}"
        r = await self.helpers.request(workspace_url, headers=self.authorization_headers)
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
        r = await self.helpers.request(environment_url, headers=self.authorization_headers)
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
        r = await self.helpers.request(collection_url, headers=self.authorization_headers)
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

    def add_json_to_zip(self, zip_path, data, filename):
        with zipfile.ZipFile(zip_path, "a") as zipf:
            json_content = json.dumps(data, indent=4)
            zipf.writestr(filename, json_content)
