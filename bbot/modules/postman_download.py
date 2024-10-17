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
        output_folder = self.config.get("output_folder")
        if output_folder:
            self.output_dir = Path(output_folder) / "postman_workspaces"
        else:
            self.output_dir = self.scan.home / "postman_workspaces"
        self.helpers.mkdir(self.output_dir)
        return await self.require_api_key()

    def prepare_api_request(self, url, kwargs):
        kwargs["headers"]["X-Api-Key"] = self.api_key
        return url, kwargs

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
            data = await self.request_workspace(workspace_id)
            workspace = data["workspace"]
            environments = data["environments"]
            collections = data["collections"]
            in_scope = await self.validate_workspace(workspace, environments, collections)
            if in_scope:
                workspace_path = self.save_workspace(workspace, environments, collections)
                if workspace_path:
                    self.verbose(f"Downloaded workspace from {repo_url} to {workspace_path}")
                    codebase_event = self.make_event(
                        {"path": str(workspace_path)}, "FILESYSTEM", tags=["postman", "workspace"], parent=event
                    )
                    await self.emit_event(
                        codebase_event,
                        context=f"{{module}} downloaded postman workspace at {repo_url} to {{event.type}}: {workspace_path}",
                    )
            else:
                self.verbose(
                    f"Failed to validate {repo_url} is in our scope as it does not contain any in-scope dns_names / emails, skipping download"
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

    async def request_workspace(self, id):
        data = {"workspace": {}, "environments": [], "collections": []}
        workspace = await self.get_workspace(id)
        if workspace:
            # Main Workspace
            name = workspace["name"]
            data["workspace"] = workspace

            # Workspace global variables
            self.verbose(f"Downloading globals for workspace {name}")
            globals = await self.get_globals(id)
            data["environments"].append(globals)

            # Workspace Environments
            workspace_environments = workspace.get("environments", [])
            if workspace_environments:
                self.verbose(f"Downloading environments for workspace {name}")
                for _ in workspace_environments:
                    environment_id = _["uid"]
                    environment = await self.get_environment(environment_id)
                    data["environments"].append(environment)

            # Workspace Collections
            workspace_collections = workspace.get("collections", [])
            if workspace_collections:
                self.verbose(f"Downloading collections for workspace {name}")
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

    def save_workspace(self, workspace, environments, collections):
        zip_path = None
        # Create a folder for the workspace
        name = workspace["name"]
        id = workspace["id"]
        folder = self.output_dir / name
        self.helpers.mkdir(folder)
        zip_path = folder / f"{id}.zip"

        # Main Workspace
        self.add_json_to_zip(zip_path, workspace, f"{name}.postman_workspace.json")

        # Workspace Environments
        if environments:
            for environment in environments:
                environment_id = environment["id"]
                self.add_json_to_zip(zip_path, environment, f"{environment_id}.postman_environment.json")

            # Workspace Collections
            if collections:
                for collection in collections:
                    collection_name = collection["info"]["name"]
                    self.add_json_to_zip(zip_path, collection, f"{collection_name}.postman_collection.json")
        return zip_path

    def add_json_to_zip(self, zip_path, data, filename):
        with zipfile.ZipFile(zip_path, "a") as zipf:
            json_content = json.dumps(data, indent=4)
            zipf.writestr(filename, json_content)
