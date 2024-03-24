import io
import json
import tarfile
from pathlib import Path
from bbot.modules.base import BaseModule


class docker_pull(BaseModule):
    watched_events = ["CODE_REPOSITORY"]
    produced_events = ["FILESYSTEM"]
    flags = ["passive", "safe", "slow"]
    meta = {"description": "Download images from a docker repository"}
    options = {"all_tags": False, "output_folder": ""}
    options_desc = {
        "all_tags": "Download all tags from each registry (Default False)",
        "output_folder": "Folder to download docker repositories to",
    }

    scope_distance_modifier = 2

    async def setup(self):
        self.headers = {
            "Accept": ",".join(
                [
                    "application/vnd.docker.distribution.manifest.v2+json",
                    "application/vnd.docker.distribution.manifest.list.v2+json",
                    "application/vnd.docker.distribution.manifest.v1+json",
                ]
            )
        }
        self.all_tags = self.config.get("all_tags", True)
        output_folder = self.config.get("output_folder")
        if output_folder:
            self.output_dir = Path(output_folder) / "docker_images"
        else:
            self.output_dir = self.scan.home / "docker_images"
        self.helpers.mkdir(self.output_dir)
        return await super().setup()

    async def filter_event(self, event):
        if event.type == "CODE_REPOSITORY":
            if "docker" not in event.tags:
                return False, "event is not a docker repository"
        return True

    async def handle_event(self, event):
        repo_url = event.data.get("url")
        repo_path = await self.download_docker_repo(repo_url)
        if repo_path:
            self.verbose(f"Downloaded docker repository {repo_url} to {repo_path}")
            codebase_event = self.make_event(
                {"path": str(repo_path)}, "FILESYSTEM", tags=["docker", "tarball"], source=event
            )
            codebase_event.scope_distance = event.scope_distance
            await self.emit_event(codebase_event)

    def get_registry_and_repository(self, repository_url):
        """Function to get the registry and repository from a html repository URL."""
        if repository_url.startswith("https://hub.docker.com/r/"):
            registry = "https://registry-1.docker.io"
            repository = repository_url.replace("https://hub.docker.com/r/", "")
        else:
            repository = "/".join(repository_url.split("/")[-2:])
            registry = repository_url.replace(repository, "")
        return registry, repository

    async def docker_api_request(self, url: str):
        """Make a request to the URL if that fails try to obtain an authentication token and try again."""
        for _ in range(2):
            response = await self.helpers.request(url, headers=self.headers, follow_redirects=True)
            if response is not None and response.status_code != 401:
                return response
            www_authenticate_headers = response.headers.get("www-authenticate", "")
            if not www_authenticate_headers:
                self.log.error(f"Could not obtain authenticate headers from {url}")
                break
            try:
                realm = www_authenticate_headers.split('realm="')[1].split('"')[0]
                service = www_authenticate_headers.split('service="')[1].split('"')[0]
                scope = www_authenticate_headers.split('scope="')[1].split('"')[0]
            except IndexError:
                self.log.error(f"Could not obtain realm, service or scope from {url}")
                break
            auth_url = f"{realm}?service={service}&scope={scope}"
            auth_response = await self.helpers.request(auth_url)
            if not auth_response:
                self.log.error(f"Could not obtain token from {auth_url}")
                break
            auth_json = auth_response.json()
            token = auth_json["token"]
            self.headers.update({"Authorization": f"Bearer {token}"})
        return None

    async def get_tags(self, registry, repository):
        url = f"{registry}/v2/{repository}/tags/list"
        r = await self.docker_api_request(url)
        if r is None or r.status_code != 200:
            self.log.warning(f"Could not retrieve all tags for {repository} asuming tag:latest only.")
            return ["latest"]
        try:
            tags = r.json()["tags"]
            self.debug(f"Tags for {repository}: {tags}")
            if self.all_tags:
                return tags
            else:
                if "latest" in tags:
                    return ["latest"]
                else:
                    return tags[-1]
        except KeyError:
            self.log.error(f"Could not retrieve tags for {repository}.")
            return ["latest"]

    async def get_manifest(self, registry, repository, tag):
        url = f"{registry}/v2/{repository}/manifests/{tag}"
        r = await self.docker_api_request(url)
        if r is None or r.status_code != 200:
            self.log.error(f"Could not retrieve manifest for {repository}:{tag}.")
            return None
        response_json = r.json()
        if response_json["mediaType"] == "application/vnd.docker.distribution.manifest.v2+json":
            return response_json
        elif response_json["mediaType"] == "application/vnd.docker.distribution.manifest.list.v2+json":
            for manifest in response_json["manifests"]:
                if manifest["platform"]["os"] == "linux" and manifest["platform"]["architecture"] == "amd64":
                    return await self.get_manifest(registry, repository, manifest["digest"])
        else:
            return r.json()

    async def get_layers(self, manifest):
        schema_version = manifest.get("schemaVersion", 2)
        if schema_version == 1:
            return [l["blobSum"] for l in manifest.get("fsLayers", [])]
        elif schema_version == 2:
            return [l["digest"] for l in manifest.get("layers", [])]
        else:
            return []

    async def download_blob(self, registry, repository, digest):
        url = f"{registry}/v2/{repository}/blobs/{digest}"
        r = await self.docker_api_request(url)
        if r is None or r.status_code != 200:
            return None
        else:
            return r.content

    async def create_local_manifest(self, config, layers):
        manifest = [{"Config": config, "RepoTags": [], "Layers": layers}]
        return json.dumps(manifest).encode()

    async def download_and_get_filename(self, registry, repository, digest):
        blob = await self.download_blob(registry, repository, digest)
        hash_func = digest.split(":")[0]
        digest = digest.split(":")[1]
        filename = f"blobs/{hash_func}/{digest}"
        return blob, filename

    async def write_file_to_tar(self, tar, filename, file_content):
        file_io = io.BytesIO(file_content)
        file_info = tarfile.TarInfo(name=filename)
        file_info.size = len(file_io.getvalue())
        file_io.seek(0)
        tar.addfile(file_info, file_io)

    async def download_docker_repo(self, repository_url):
        registry, repository = self.get_registry_and_repository(repository_url)
        tags = await self.get_tags(registry, repository)
        for tag in tags:
            self.verbose(f"Downloading {repository}:{tag}")
            tar_file = await self.download_and_write_to_tar(registry, repository, tag)
        return tar_file

    async def download_and_write_to_tar(self, registry, repository, tag):
        output_tar = self.output_dir / f"{repository.replace('/', '_')}_{tag}.tar"
        with tarfile.open(output_tar, mode="w") as tar:
            manifest = await self.get_manifest(registry, repository, tag)
            config_file, config_filename = await self.download_and_get_filename(
                registry, repository, manifest.get("config", {}).get("digest")
            )
            await self.write_file_to_tar(tar, config_filename, config_file)

            layer_filenames = []
            for layer_digest in await self.get_layers(manifest):
                blob, layer_filename = await self.download_and_get_filename(registry, repository, layer_digest)
                layer_filenames.append(layer_filename)
                await self.write_file_to_tar(tar, layer_filename, blob)

            manifest_json = await self.create_local_manifest(config_filename, layer_filenames)
            await self.write_file_to_tar(tar, "manifest.json", manifest_json)
        return output_tar
