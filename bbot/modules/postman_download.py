import zipfile
import json
from pathlib import Path
from bbot.modules.templates.postman import postman
from bbot.core.config.models import BaseModuleConfig, Field


class postman_download(postman):
    watched_events = ["CODE_REPOSITORY"]
    produced_events = ["FILESYSTEM"]
    flags = ["safe", "passive", "subdomain-enum", "code-enum", "download"]
    meta = {
        "description": "Download workspaces, collections, requests from Postman",
        "created_date": "2024-09-07",
        "author": "@domwhewell-sage",
    }

    class Config(BaseModuleConfig):
        output_folder: str = Field(
            "",
            description="Folder to download postman workspaces to. If not specified, downloaded workspaces will be deleted when the scan completes, to minimize disk usage.",
        )
        api_key: str | list[str] = Field("", description="Postman API Key", sensitive=True, mandatory=True)

    scope_distance_modifier = 2

    async def setup(self):
        output_folder = self.config.get("output_folder", "")
        if output_folder:
            self.output_dir = Path(output_folder) / "postman_workspaces"
        else:
            self.output_dir = self.scan.temp_dir / "postman_workspaces"
        self.helpers.mkdir(self.output_dir)
        return await super().setup()

    async def filter_event(self, event):
        if event.type == "CODE_REPOSITORY":
            if "postman" not in event.tags:
                return False, "event is not a postman workspace"
        return True

    async def handle_event(self, event):
        repo_url = event.url
        workspace_id = await self.get_workspace_id(repo_url)
        if workspace_id:
            self.verbose(f"Found workspace ID {workspace_id} for {repo_url}")
            data = await self.request_workspace(workspace_id)
            workspace = data["workspace"]
            environments = data["environments"]
            collections = data["collections"]
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

    def save_workspace(self, workspace, environments, collections):
        zip_path = None
        name = workspace["name"]
        id = workspace["id"]
        safe_name = self.helpers.tagify(name)
        folder = self.output_dir / safe_name
        if not folder.resolve().is_relative_to(self.output_dir.resolve()):
            self.warning(f"Workspace name {name!r} resulted in path traversal, skipping")
            return None
        self.helpers.mkdir(folder)
        zip_path = folder / f"{id}.zip"

        # Main Workspace
        self.add_json_to_zip(zip_path, workspace, f"{safe_name}.postman_workspace.json")

        # Workspace Environments
        if environments:
            for environment in environments:
                environment_id = environment["id"]
                self.add_json_to_zip(zip_path, environment, f"{environment_id}.postman_environment.json")

            # Workspace Collections
            if collections:
                for collection in collections:
                    collection_name = collection["info"]["name"]
                    safe_collection_name = self.helpers.tagify(collection_name)
                    self.add_json_to_zip(zip_path, collection, f"{safe_collection_name}.postman_collection.json")
        return zip_path

    def add_json_to_zip(self, zip_path, data, filename):
        with zipfile.ZipFile(zip_path, "a") as zipf:
            json_content = json.dumps(data, indent=4)
            zipf.writestr(filename, json_content)
