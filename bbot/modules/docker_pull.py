import io
import json
import tarfile
from pathlib import Path
from bbot.modules.base import BaseModule


class docker_pull(BaseModule):
    watched_events = ["CODE_REPOSITORY"]
    produced_events = ["FILESYSTEM"]
    flags = ["passive", "safe", "slow", "code-enum"]
    meta = {
        "description": "Download images from a docker repository",
        "created_date": "2024-03-24",
        "author": "@domwhewell-sage",
    }
    options = {"all_tags": False, "output_folder": ""}
    options_desc = {
        "all_tags": "Download all tags from each registry (Default False)",
        "output_folder": "Folder to download docker repositories to. If not specified, downloaded docker images will be deleted when the scan completes, to minimize disk usage.",
    }

    scope_distance_modifier = 2

    async def setup(self):
        self.headers = {
            "Accept": ",".join(
                [
                    "application/vnd.docker.distribution.manifest.v2+json",
                    "application/vnd.docker.distribution.manifest.list.v2+json",
                    "application/vnd.docker.distribution.manifest.v1+json",
                    "application/vnd.oci.image.manifest.v1+json",
                ]
            )
        }
        self.all_tags = self.config.get("all_tags", True)
        output_folder = self.config.get("output_folder", "")
        if output_folder:
            self.output_dir = Path(output_folder) / "docker_images"
        else:
            self.output_dir = self.scan.temp_dir / "docker_images"
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
                {"path": str(repo_path), "description": f"Docker image repository: {repo_url}"},
                "FILESYSTEM",
                tags=["docker", "tarball"],
                parent=event,
            )
            if codebase_event:
                await self.emit_event(
                    codebase_event, context=f"{{module}} downloaded Docker image to {{event.type}}: {repo_path}"
                )

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
            try:
                www_authenticate_headers = response.headers.get("www-authenticate", "")
                realm = www_authenticate_headers.split('realm="')[1].split('"')[0]
                service = www_authenticate_headers.split('service="')[1].split('"')[0]
                scope = www_authenticate_headers.split('scope="')[1].split('"')[0]
            except (KeyError, IndexError):
                self.log.warning(f"Could not obtain realm, service or scope from {url}")
                break
            auth_url = f"{realm}?service={service}&scope={scope}"
            auth_response = await self.helpers.request(auth_url)
            if not auth_response:
                self.log.warning(f"Could not obtain token from {auth_url}")
                break
            auth_json = auth_response.json()
            token = auth_json["token"]
            self.headers.update({"Authorization": f"Bearer {token}"})
        return None

    async def get_tags(self, registry, repository):
        url = f"{registry}/v2/{repository}/tags/list"
        r = await self.docker_api_request(url)
        if r is None or r.status_code != 200:
            self.log.warning(f"Could not retrieve all tags for {repository} assuming tag:latest only.")
            self.log.debug(f"Response: {r}")
            return ["latest"]
        try:
            tags = r.json().get("tags", ["latest"])
            self.debug(f"Tags for {repository}: {tags}")
            if self.all_tags:
                return tags
            else:
                if "latest" in tags:
                    return ["latest"]
                else:
                    return [tags[-1]]
        except (KeyError, IndexError):
            self.log.warning(f"Could not retrieve tags for {repository}.")
            return ["latest"]

    async def get_manifest(self, registry, repository, tag):
        url = f"{registry}/v2/{repository}/manifests/{tag}"
        r = await self.docker_api_request(url)
        if r is None or r.status_code != 200:
            self.log.warning(f"Could not retrieve manifest for {repository}:{tag}.")
            self.log.debug(f"Response: {r}")
            return {}
        response_json = r.json()
        if response_json.get("manifests", []):
            for manifest in response_json["manifests"]:
                if manifest["platform"]["os"] == "linux" and manifest["platform"]["architecture"] == "amd64":
                    return await self.get_manifest(registry, repository, manifest["digest"])
        return response_json

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

    async def create_local_manifest(self, config, repository, tag, layers):
        manifest = [{"Config": config, "RepoTags": [f"{repository}:{tag}"], "Layers": layers}]
        return json.dumps(manifest).encode()

    async def download_and_get_filename(self, registry, repository, digest):
        if ":" not in digest:
            return None, None
        blob = await self.download_blob(registry, repository, digest)
        hash_func = digest.split(":")[0]
        digest = digest.split(":")[1]
        filename = f"blobs/{hash_func}/{digest}"
        return blob, filename

    async def write_file_to_tar(self, tar, filename, file_content):
        if filename and file_content:
            file_io = io.BytesIO(file_content)
            file_info = tarfile.TarInfo(name=filename)
            file_info.size = len(file_io.getvalue())
            file_io.seek(0)
            tar.addfile(file_info, file_io)

    async def download_docker_repo(self, repository_url):
        registry, repository = self.get_registry_and_repository(repository_url)
        tags = await self.get_tags(registry, repository)
        for tag in tags:
            self.info(f"Downloading {repository}:{tag}")
            tar_file = await self.download_and_write_to_tar(registry, repository, tag)
        return tar_file

    async def download_and_write_to_tar(self, registry, repository, tag):
        output_tar = self.output_dir / f"{repository.replace('/', '_')}_{tag}.tar"
        with tarfile.open(output_tar, mode="w") as tar:
            manifest = await self.get_manifest(registry, repository, tag)
            config_file, config_filename = await self.download_and_get_filename(
                registry, repository, manifest.get("config", {}).get("digest", "")
            )
            await self.write_file_to_tar(tar, config_filename, config_file)

            layer_filenames = []
            layer_digests = await self.get_layers(manifest)
            for i, layer_digest in enumerate(layer_digests):
                self.verbose(f"Downloading layer {i + 1}/{len(layer_digests)} from {repository}:{tag}")
                blob, layer_filename = await self.download_and_get_filename(registry, repository, layer_digest)
                layer_filenames.append(layer_filename)
                await self.write_file_to_tar(tar, layer_filename, blob)

            manifest_json = await self.create_local_manifest(config_filename, repository, tag, layer_filenames)
            await self.write_file_to_tar(tar, "manifest.json", manifest_json)
        return output_tar
