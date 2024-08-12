import io
import tarfile
from pathlib import Path

from .base import ModuleTestBase


class TestDockerPull(ModuleTestBase):
    modules_overrides = ["speculate", "dockerhub", "docker_pull"]

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://hub.docker.com/v2/users/blacklanternsecurity",
            json={
                "id": "f90895d9cf484d9182c6dbbef2632329",
                "uuid": "f90895d9-cf48-4d91-82c6-dbbef2632329",
                "username": "blacklanternsecurity",
                "full_name": "",
                "location": "",
                "company": "Black Lantern Security",
                "profile_url": "https://github.com/blacklanternsecurity",
                "date_joined": "2022-08-29T15:27:10.227081Z",
                "gravatar_url": "",
                "gravatar_email": "",
                "type": "User",
            },
        )
        module_test.httpx_mock.add_response(
            url="https://hub.docker.com/v2/repositories/blacklanternsecurity?page_size=25&page=1",
            json={
                "count": 2,
                "next": None,
                "previous": None,
                "results": [
                    {
                        "name": "helloworld",
                        "namespace": "blacklanternsecurity",
                        "repository_type": "image",
                        "status": 1,
                        "status_description": "active",
                        "description": "",
                        "is_private": False,
                        "star_count": 0,
                        "pull_count": 1,
                        "last_updated": "2021-12-20T17:19:58.88296Z",
                        "date_registered": "2021-12-20T17:19:58.507614Z",
                        "affiliation": "",
                        "media_types": ["application/vnd.docker.container.image.v1+json"],
                        "content_types": ["image"],
                        "categories": [],
                    },
                    {
                        "name": "testimage",
                        "namespace": "blacklanternsecurity",
                        "repository_type": "image",
                        "status": 1,
                        "status_description": "active",
                        "description": "",
                        "is_private": False,
                        "star_count": 0,
                        "pull_count": 1,
                        "last_updated": "2022-01-10T20:16:46.170738Z",
                        "date_registered": "2022-01-07T13:28:59.756641Z",
                        "affiliation": "",
                        "media_types": ["application/vnd.docker.container.image.v1+json"],
                        "content_types": ["image"],
                        "categories": [],
                    },
                ],
            },
        )
        module_test.httpx_mock.add_response(
            url="https://registry-1.docker.io/v2/blacklanternsecurity/helloworld/tags/list",
            json={
                "errors": [
                    {
                        "code": "UNAUTHORIZED",
                        "message": "authentication required",
                        "detail": [
                            {
                                "Type": "repository",
                                "Class": "",
                                "Name": "blacklanternsecurity/helloworld",
                                "Action": "pull",
                            }
                        ],
                    }
                ]
            },
            headers={
                "www-authenticate": 'Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="blacklanternsecurity/helloworld:pull"'
            },
            status_code=401,
        )
        module_test.httpx_mock.add_response(
            url="https://registry-1.docker.io/v2/blacklanternsecurity/testimage/tags/list",
            json={
                "errors": [
                    {
                        "code": "UNAUTHORIZED",
                        "message": "authentication required",
                        "detail": [
                            {
                                "Type": "repository",
                                "Class": "",
                                "Name": "blacklanternsecurity/testimage",
                                "Action": "pull",
                            }
                        ],
                    }
                ]
            },
            headers={
                "www-authenticate": 'Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="blacklanternsecurity/testimage:pull"'
            },
            status_code=401,
        )
        module_test.httpx_mock.add_response(
            url="https://auth.docker.io/token?service=registry.docker.io&scope=blacklanternsecurity/helloworld:pull",
            json={
                "token": "QWERTYUIOPASDFGHJKLZXCBNM",
            },
        )
        module_test.httpx_mock.add_response(
            url="https://auth.docker.io/token?service=registry.docker.io&scope=blacklanternsecurity/testimage:pull",
            json={
                "token": "QWERTYUIOPASDFGHJKLZXCBNM",
            },
        )
        module_test.httpx_mock.add_response(
            url="https://registry-1.docker.io/v2/blacklanternsecurity/helloworld/tags/list",
            json={
                "name": "blacklanternsecurity/helloworld",
                "tags": [
                    "dev",
                    "latest",
                ],
            },
        )
        module_test.httpx_mock.add_response(
            url="https://registry-1.docker.io/v2/blacklanternsecurity/testimage/tags/list",
            json={
                "name": "blacklanternsecurity/testimage",
                "tags": [
                    "dev",
                    "latest",
                ],
            },
        )
        module_test.httpx_mock.add_response(
            url="https://registry-1.docker.io/v2/blacklanternsecurity/helloworld/manifests/latest",
            json={
                "schemaVersion": 2,
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "config": {
                    "mediaType": "application/vnd.docker.container.image.v1+json",
                    "size": 8614,
                    "digest": "sha256:a9910947b74a4f0606cfc8669ae8808d2c328beaee9e79f489dc17df14cd50b1",
                },
                "layers": [
                    {
                        "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                        "size": 29124181,
                        "digest": "sha256:8a1e25ce7c4f75e372e9884f8f7b1bedcfe4a7a7d452eb4b0a1c7477c9a90345",
                    },
                ],
            },
        )
        module_test.httpx_mock.add_response(
            url="https://registry-1.docker.io/v2/blacklanternsecurity/testimage/manifests/latest",
            json={
                "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
                "schemaVersion": 2,
                "manifests": [
                    {
                        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                        "platform": {"os": "linux", "architecture": "s390x"},
                        "digest": "sha256:3e8a8b63afab946f4a64c1dc63563d91b2cb1e5eadadac1eff20231695c53d24",
                        "size": 1953,
                    },
                    {
                        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                        "platform": {"os": "linux", "architecture": "amd64"},
                        "digest": "sha256:7c75331408141f1e3ef37eac7c45938fbfb0d421a86201ad45d2ab8b70ddd527",
                        "size": 1953,
                    },
                    {
                        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                        "platform": {"os": "linux", "architecture": "ppc64le"},
                        "digest": "sha256:33d30a60996db4bc8158151ce516a8503cc56ce8d146e450e117a57ca5bf06e7",
                        "size": 1953,
                    },
                    {
                        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                        "platform": {"os": "linux", "architecture": "arm64", "variant": "v8"},
                        "digest": "sha256:d0eacd0089db7309a5ce40ec3334fcdd4ce7d67324f1ccc4433dd4fae4a771a4",
                        "size": 1953,
                    },
                ],
            },
        )
        module_test.httpx_mock.add_response(
            url="https://registry-1.docker.io/v2/blacklanternsecurity/helloworld/blobs/sha256:a9910947b74a4f0606cfc8669ae8808d2c328beaee9e79f489dc17df14cd50b1",
            json={
                "architecture": "amd64",
                "config": {
                    "Env": [
                        "PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                        "LANG=C.UTF-8",
                        "GPG_KEY=QWERTYUIOPASDFGHJKLZXCBNM",
                        "PYTHON_VERSION=3.10.14",
                        "PYTHON_PIP_VERSION=23.0.1",
                        "PYTHON_SETUPTOOLS_VERSION=65.5.1",
                        "PYTHON_GET_PIP_URL=https://github.com/pypa/get-pip/raw/dbf0c85f76fb6e1ab42aa672ffca6f0a675d9ee4/public/get-pip.py",
                        "PYTHON_GET_PIP_SHA256=dfe9fd5c28dc98b5ac17979a953ea550cec37ae1b47a5116007395bfacff2ab9",
                        "LC_ALL=C.UTF-8",
                        "PIP_NO_CACHE_DIR=off",
                    ],
                    "Entrypoint": ["helloworld"],
                    "WorkingDir": "/root",
                    "ArgsEscaped": True,
                    "OnBuild": None,
                },
                "created": "2024-03-24T03:46:29.788993495Z",
                "history": [
                    {
                        "created": "2024-03-12T01:21:01.529814652Z",
                        "created_by": "/bin/sh -c #(nop) ADD file:b86ae1c7ca3586d8feedcd9ff1b2b1e8ab872caf6587618f1da689045a5d7ae4 in / ",
                    },
                    {
                        "created": "2024-03-12T01:21:01.866693306Z",
                        "created_by": '/bin/sh -c #(nop)  CMD ["bash"]',
                        "empty_layer": True,
                    },
                    {
                        "created": "2024-03-20T18:33:29Z",
                        "created_by": "ENV PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                        "comment": "buildkit.dockerfile.v0",
                        "empty_layer": True,
                    },
                    {
                        "created": "2024-03-20T18:33:29Z",
                        "created_by": "ENV LANG=C.UTF-8",
                        "comment": "buildkit.dockerfile.v0",
                        "empty_layer": True,
                    },
                    {
                        "created": "2024-03-20T18:33:29Z",
                        "created_by": "RUN /bin/sh -c set -eux; \tapt-get update; \tapt-get install -y --no-install-recommends \t\tca-certificates \t\tnetbase \t\ttzdata \t; \trm -rf /var/lib/apt/lists/* # buildkit",
                        "comment": "buildkit.dockerfile.v0",
                    },
                    {
                        "created": "2024-03-20T18:33:29Z",
                        "created_by": "ENV GPG_KEY=QWERTYUIOPASDFGHJKLZXCBNM",
                        "comment": "buildkit.dockerfile.v0",
                        "empty_layer": True,
                    },
                    {
                        "created": "2024-03-20T18:33:29Z",
                        "created_by": "ENV PYTHON_VERSION=3.10.14",
                        "comment": "buildkit.dockerfile.v0",
                        "empty_layer": True,
                    },
                    {
                        "created": "2024-03-20T18:33:29Z",
                        "created_by": 'RUN /bin/sh -c set -eux; \t\tsavedAptMark="$(apt-mark showmanual)"; \tapt-get update; \tapt-get install -y --no-install-recommends \t\tdpkg-dev \t\tgcc \t\tgnupg \t\tlibbluetooth-dev \t\tlibbz2-dev \t\tlibc6-dev \t\tlibdb-dev \t\tlibexpat1-dev \t\tlibffi-dev \t\tlibgdbm-dev \t\tliblzma-dev \t\tlibncursesw5-dev \t\tlibreadline-dev \t\tlibsqlite3-dev \t\tlibssl-dev \t\tmake \t\ttk-dev \t\tuuid-dev \t\twget \t\txz-utils \t\tzlib1g-dev \t; \t\twget -O python.tar.xz "https://www.python.org/ftp/python/${PYTHON_VERSION%%[a-z]*}/Python-$PYTHON_VERSION.tar.xz"; \twget -O python.tar.xz.asc "https://www.python.org/ftp/python/${PYTHON_VERSION%%[a-z]*}/Python-$PYTHON_VERSION.tar.xz.asc"; \tGNUPGHOME="$(mktemp -d)"; export GNUPGHOME; \tgpg --batch --keyserver hkps://keys.openpgp.org --recv-keys "$GPG_KEY"; \tgpg --batch --verify python.tar.xz.asc python.tar.xz; \tgpgconf --kill all; \trm -rf "$GNUPGHOME" python.tar.xz.asc; \tmkdir -p /usr/src/python; \ttar --extract --directory /usr/src/python --strip-components=1 --file python.tar.xz; \trm python.tar.xz; \t\tcd /usr/src/python; \tgnuArch="$(dpkg-architecture --query DEB_BUILD_GNU_TYPE)"; \t./configure \t\t--build="$gnuArch" \t\t--enable-loadable-sqlite-extensions \t\t--enable-optimizations \t\t--enable-option-checking=fatal \t\t--enable-shared \t\t--with-lto \t\t--with-system-expat \t\t--without-ensurepip \t; \tnproc="$(nproc)"; \tEXTRA_CFLAGS="$(dpkg-buildflags --get CFLAGS)"; \tLDFLAGS="$(dpkg-buildflags --get LDFLAGS)"; \tLDFLAGS="${LDFLAGS:--Wl},--strip-all"; \tmake -j "$nproc" \t\t"EXTRA_CFLAGS=${EXTRA_CFLAGS:-}" \t\t"LDFLAGS=${LDFLAGS:-}" \t\t"PROFILE_TASK=${PROFILE_TASK:-}" \t; \trm python; \tmake -j "$nproc" \t\t"EXTRA_CFLAGS=${EXTRA_CFLAGS:-}" \t\t"LDFLAGS=${LDFLAGS:--Wl},-rpath=\'\\$\\$ORIGIN/../lib\'" \t\t"PROFILE_TASK=${PROFILE_TASK:-}" \t\tpython \t; \tmake install; \t\tcd /; \trm -rf /usr/src/python; \t\tfind /usr/local -depth \t\t\\( \t\t\t\\( -type d -a \\( -name test -o -name tests -o -name idle_test \\) \\) \t\t\t-o \\( -type f -a \\( -name \'*.pyc\' -o -name \'*.pyo\' -o -name \'libpython*.a\' \\) \\) \t\t\\) -exec rm -rf \'{}\' + \t; \t\tldconfig; \t\tapt-mark auto \'.*\' > /dev/null; \tapt-mark manual $savedAptMark; \tfind /usr/local -type f -executable -not \\( -name \'*tkinter*\' \\) -exec ldd \'{}\' \';\' \t\t| awk \'/=>/ { so = $(NF-1); if (index(so, "/usr/local/") == 1) { next }; gsub("^/(usr/)?", "", so); printf "*%s\\n", so }\' \t\t| sort -u \t\t| xargs -r dpkg-query --search \t\t| cut -d: -f1 \t\t| sort -u \t\t| xargs -r apt-mark manual \t; \tapt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false; \trm -rf /var/lib/apt/lists/*; \t\tpython3 --version # buildkit',
                        "comment": "buildkit.dockerfile.v0",
                    },
                    {
                        "created": "2024-03-20T18:33:29Z",
                        "created_by": 'RUN /bin/sh -c set -eux; \tfor src in idle3 pydoc3 python3 python3-config; do \t\tdst="$(echo "$src" | tr -d 3)"; \t\t[ -s "/usr/local/bin/$src" ]; \t\t[ ! -e "/usr/local/bin/$dst" ]; \t\tln -svT "$src" "/usr/local/bin/$dst"; \tdone # buildkit',
                        "comment": "buildkit.dockerfile.v0",
                    },
                    {
                        "created": "2024-03-20T18:33:29Z",
                        "created_by": "ENV PYTHON_PIP_VERSION=23.0.1",
                        "comment": "buildkit.dockerfile.v0",
                        "empty_layer": True,
                    },
                    {
                        "created": "2024-03-20T18:33:29Z",
                        "created_by": "ENV PYTHON_SETUPTOOLS_VERSION=65.5.1",
                        "comment": "buildkit.dockerfile.v0",
                        "empty_layer": True,
                    },
                    {
                        "created": "2024-03-20T18:33:29Z",
                        "created_by": "ENV PYTHON_GET_PIP_URL=https://github.com/pypa/get-pip/raw/dbf0c85f76fb6e1ab42aa672ffca6f0a675d9ee4/public/get-pip.py",
                        "comment": "buildkit.dockerfile.v0",
                        "empty_layer": True,
                    },
                    {
                        "created": "2024-03-20T18:33:29Z",
                        "created_by": "ENV PYTHON_GET_PIP_SHA256=dfe9fd5c28dc98b5ac17979a953ea550cec37ae1b47a5116007395bfacff2ab9",
                        "comment": "buildkit.dockerfile.v0",
                        "empty_layer": True,
                    },
                    {
                        "created": "2024-03-20T18:33:29Z",
                        "created_by": 'RUN /bin/sh -c set -eux; \t\tsavedAptMark="$(apt-mark showmanual)"; \tapt-get update; \tapt-get install -y --no-install-recommends wget; \t\twget -O get-pip.py "$PYTHON_GET_PIP_URL"; \techo "$PYTHON_GET_PIP_SHA256 *get-pip.py" | sha256sum -c -; \t\tapt-mark auto \'.*\' > /dev/null; \t[ -z "$savedAptMark" ] || apt-mark manual $savedAptMark > /dev/null; \tapt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false; \trm -rf /var/lib/apt/lists/*; \t\texport PYTHONDONTWRITEBYTECODE=1; \t\tpython get-pip.py \t\t--disable-pip-version-check \t\t--no-cache-dir \t\t--no-compile \t\t"pip==$PYTHON_PIP_VERSION" \t\t"setuptools==$PYTHON_SETUPTOOLS_VERSION" \t; \trm -f get-pip.py; \t\tpip --version # buildkit',
                        "comment": "buildkit.dockerfile.v0",
                    },
                    {
                        "created": "2024-03-20T18:33:29Z",
                        "created_by": 'CMD ["python3"]',
                        "comment": "buildkit.dockerfile.v0",
                        "empty_layer": True,
                    },
                    {
                        "created": "2024-03-24T03:45:39.322168741Z",
                        "created_by": "ENV LANG=C.UTF-8",
                        "comment": "buildkit.dockerfile.v0",
                        "empty_layer": True,
                    },
                    {
                        "created": "2024-03-24T03:45:39.322168741Z",
                        "created_by": "ENV LC_ALL=C.UTF-8",
                        "comment": "buildkit.dockerfile.v0",
                        "empty_layer": True,
                    },
                    {
                        "created": "2024-03-24T03:45:39.322168741Z",
                        "created_by": "ENV PIP_NO_CACHE_DIR=off",
                        "comment": "buildkit.dockerfile.v0",
                        "empty_layer": True,
                    },
                    {
                        "created": "2024-03-24T03:45:39.322168741Z",
                        "created_by": "WORKDIR /usr/src/helloworld",
                        "comment": "buildkit.dockerfile.v0",
                    },
                    {
                        "created": "2024-03-24T03:45:52.226201188Z",
                        "created_by": "RUN /bin/sh -c apt-get update && apt-get install -y openssl gcc git make unzip curl wget vim nano sudo # buildkit",
                        "comment": "buildkit.dockerfile.v0",
                    },
                    {
                        "created": "2024-03-24T03:45:52.391597947Z",
                        "created_by": "COPY . . # buildkit",
                        "comment": "buildkit.dockerfile.v0",
                    },
                    {
                        "created": "2024-03-24T03:46:29.76589069Z",
                        "created_by": "RUN /bin/sh -c pip install . # buildkit",
                        "comment": "buildkit.dockerfile.v0",
                    },
                    {
                        "created": "2024-03-24T03:46:29.788993495Z",
                        "created_by": "WORKDIR /root",
                        "comment": "buildkit.dockerfile.v0",
                    },
                    {
                        "created": "2024-03-24T03:46:29.788993495Z",
                        "created_by": 'ENTRYPOINT ["helloworld"]',
                        "comment": "buildkit.dockerfile.v0",
                        "empty_layer": True,
                    },
                ],
                "os": "linux",
                "rootfs": {
                    "type": "layers",
                    "diff_ids": [
                        "sha256:a483da8ab3e941547542718cacd3258c6c705a63e94183c837c9bc44eb608999",
                        "sha256:c8f253aef5606f6716778771171c3fdf6aa135b76a5fa8bf66ba45c12c15b540",
                        "sha256:b4a9dcc697d250c7be53887bb8e155c8f7a06f9c63a3aa627c647bb4a426d3f0",
                        "sha256:120fda24c420b4e5d52f1c288b35c75b07969057bce41ec34cfb05606b2d7c11",
                        "sha256:c2287f03e33f4896b2720f0cb64e6b6050759a3eb5914e531e98fc3499b4e687",
                        "sha256:afe6e55a5cf240c050a4d2b72ec7b7d009a131cba8fe2753e453a8e62ef7e45c",
                        "sha256:ae6df275ba2e8f40c598e30588afe43f6bfa92e4915e8450b77cb5db5c89dfd5",
                        "sha256:621ab22fb386a9e663178637755b651beddc0eb4762804e74d8996cce0ddd441",
                        "sha256:4c534ad16bd2df668c0b8f637616517746ede530ba8546d85f28772bc748e06f",
                        "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
                    ],
                },
            },
        )
        module_test.httpx_mock.add_response(
            url="https://registry-1.docker.io/v2/blacklanternsecurity/testimage/manifests/sha256:7c75331408141f1e3ef37eac7c45938fbfb0d421a86201ad45d2ab8b70ddd527",
            json={
                "name": "testimage",
                "tag": "latest",
                "architecture": "amd64",
                "fsLayers": [
                    {"blobSum": "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef"},
                ],
                "history": [
                    {
                        "v1Compatibility": '{"id":"e45a5af57b00862e5ef5782a9925979a02ba2b12dff832fd0991335f4a11e5c5","parent":"31cbccb51277105ba3ae35ce33c22b69c9e3f1002e76e4c736a2e8ebff9d7b5d","created":"2014-12-31T22:57:59.178729048Z","container":"27b45f8fb11795b52e9605b686159729b0d9ca92f76d40fb4f05a62e19c46b4f","container_config":{"Hostname":"8ce6509d66e2","Domainname":"","User":"","Memory":0,"MemorySwap":0,"CpuShares":0,"Cpuset":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"PortSpecs":null,"ExposedPorts":null,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sh","-c","#(nop) CMD [/hello]"],"Image":"31cbccb51277105ba3ae35ce33c22b69c9e3f1002e76e4c736a2e8ebff9d7b5d","Volumes":null,"WorkingDir":"","Entrypoint":null,"NetworkDisabled":false,"MacAddress":"","OnBuild":[],"SecurityOpt":null,"Labels":null},"docker_version":"1.4.1","config":{"Hostname":"8ce6509d66e2","Domainname":"","User":"","Memory":0,"MemorySwap":0,"CpuShares":0,"Cpuset":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"PortSpecs":null,"ExposedPorts":null,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/hello"],"Image":"31cbccb51277105ba3ae35ce33c22b69c9e3f1002e76e4c736a2e8ebff9d7b5d","Volumes":null,"WorkingDir":"","Entrypoint":null,"NetworkDisabled":false,"MacAddress":"","OnBuild":[],"SecurityOpt":null,"Labels":null},"architecture":"amd64","os":"linux","Size":0}\n'
                    },
                    {
                        "v1Compatibility": '{"id":"e45a5af57b00862e5ef5782a9925979a02ba2b12dff832fd0991335f4a11e5c5","parent":"31cbccb51277105ba3ae35ce33c22b69c9e3f1002e76e4c736a2e8ebff9d7b5d","created":"2014-12-31T22:57:59.178729048Z","container":"27b45f8fb11795b52e9605b686159729b0d9ca92f76d40fb4f05a62e19c46b4f","container_config":{"Hostname":"8ce6509d66e2","Domainname":"","User":"","Memory":0,"MemorySwap":0,"CpuShares":0,"Cpuset":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"PortSpecs":null,"ExposedPorts":null,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sh","-c","#(nop) CMD [/hello]"],"Image":"31cbccb51277105ba3ae35ce33c22b69c9e3f1002e76e4c736a2e8ebff9d7b5d","Volumes":null,"WorkingDir":"","Entrypoint":null,"NetworkDisabled":false,"MacAddress":"","OnBuild":[],"SecurityOpt":null,"Labels":null},"docker_version":"1.4.1","config":{"Hostname":"8ce6509d66e2","Domainname":"","User":"","Memory":0,"MemorySwap":0,"CpuShares":0,"Cpuset":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"PortSpecs":null,"ExposedPorts":null,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/hello"],"Image":"31cbccb51277105ba3ae35ce33c22b69c9e3f1002e76e4c736a2e8ebff9d7b5d","Volumes":null,"WorkingDir":"","Entrypoint":null,"NetworkDisabled":false,"MacAddress":"","OnBuild":[],"SecurityOpt":null,"Labels":null},"architecture":"amd64","os":"linux","Size":0}\n'
                    },
                ],
                "schemaVersion": 1,
                "signatures": [
                    {
                        "header": {
                            "jwk": {
                                "crv": "P-256",
                                "kid": "OD6I:6DRK:JXEJ:KBM4:255X:NSAA:MUSF:E4VM:ZI6W:CUN2:L4Z6:LSF4",
                                "kty": "EC",
                                "x": "3gAwX48IQ5oaYQAYSxor6rYYc_6yjuLCjtQ9LUakg4A",
                                "y": "t72ge6kIA1XOjqjVoEOiPPAURltJFBMGDSQvEGVB010",
                            },
                            "alg": "ES256",
                        },
                        "signature": "XREm0L8WNn27Ga_iE_vRnTxVMhhYY0Zst_FfkKopg6gWSoTOZTuW4rK0fg_IqnKkEKlbD83tD46LKEGi5aIVFg",
                        "protected": "eyJmb3JtYXRMZW5ndGgiOjY2MjgsImZvcm1hdFRhaWwiOiJDbjAiLCJ0aW1lIjoiMjAxNS0wNC0wOFQxODo1Mjo1OVoifQ",
                    }
                ],
            },
        )
        temp_path = Path("/tmp/.bbot_test")
        tar_path = temp_path / "docker_pull_test.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tar:
            file_io = io.BytesIO("This is a test file".encode())
            file_info = tarfile.TarInfo(name="file.txt")
            file_info.size = len(file_io.getvalue())
            file_io.seek(0)
            tar.addfile(file_info, file_io)
        with open(tar_path, "rb") as file:
            layer_file = file.read()
        module_test.httpx_mock.add_response(
            url="https://registry-1.docker.io/v2/blacklanternsecurity/helloworld/blobs/sha256:8a1e25ce7c4f75e372e9884f8f7b1bedcfe4a7a7d452eb4b0a1c7477c9a90345",
            content=layer_file,
        )
        module_test.httpx_mock.add_response(
            url="https://registry-1.docker.io/v2/blacklanternsecurity/testimage/blobs/sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
            content=layer_file,
        )

    def check(self, module_test, events):
        filesystem_events = [
            e
            for e in events
            if e.type == "FILESYSTEM"
            and (
                "blacklanternsecurity_helloworld_latest.tar" in e.data["path"]
                or "blacklanternsecurity_testimage_latest.tar" in e.data["path"]
            )
            and "docker" in e.tags
            and e.scope_distance == 1
        ]
        assert 2 == len(filesystem_events), "Failed to download docker images"
        filesystem_event = filesystem_events[0]
        folder = Path(filesystem_event.data["path"])
        assert folder.is_file(), "Destination tar doesn't exist"
