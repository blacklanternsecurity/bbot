import io
import asyncio
import tarfile
import zipfile

from pathlib import Path
from .base import ModuleTestBase

from ...bbot_fixtures import *
from bbot.test.worker import HTTPSERVER_URL, BBOT_TEST_DIR


class TestUnarchive(ModuleTestBase):
    targets = [HTTPSERVER_URL]
    modules_overrides = ["filedownload", "http", "excavate", "speculate", "unarchive"]
    config_overrides = {
        "modules": {
            "filedownload": {
                "output_folder": bbot_test_dir / "filedownload",
            },
        }
    }

    async def setup_after_prep(self, module_test):
        temp_path = Path(BBOT_TEST_DIR)

        # Create a text file to compress
        text_file = temp_path / "test.txt"
        with open(text_file, "w") as f:
            f.write("This is a test file")
        zip_file = temp_path / "test.zip"
        zip_zip_file = temp_path / "test_zip.zip"
        bz2_file = temp_path / "test.bz2"
        xz_file = temp_path / "test.xz"
        zip7_file = temp_path / "test.7z"
        # lzma_file = temp_path / "test.lzma"
        tar_file = temp_path / "test.tar"
        tgz_file = temp_path / "test.tgz"
        commands = [
            ("7z", "a", "-aoa", f"{zip_file}", f"{text_file}"),
            ("7z", "a", "-aoa", f"{zip_zip_file}", f"{zip_file}"),
            ("tar", "-C", f"{temp_path}", "-cvjf", f"{bz2_file}", f"{text_file.name}"),
            ("tar", "-C", f"{temp_path}", "-cvJf", f"{xz_file}", f"{text_file.name}"),
            ("7z", "a", "-aoa", f"{zip7_file}", f"{text_file}"),
            # ("tar", "-C", f"{temp_path}", "--lzma", "-cvf", f"{lzma_file}", f"{text_file.name}"),
            ("tar", "-C", f"{temp_path}", "-cvf", f"{tar_file}", f"{text_file.name}"),
            ("tar", "-C", f"{temp_path}", "-cvzf", f"{tgz_file}", f"{text_file.name}"),
        ]

        for command in commands:
            process = await asyncio.create_subprocess_exec(
                *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            assert process.returncode == 0, f"Command {command} failed with error: {stderr.decode()}"

        module_test.set_expect_requests(
            dict(uri="/"),
            dict(
                response_data="""<a href="/test.zip">
                <a href="/test-zip.zip">
                <a href="/test.bz2">
                <a href="/test.xz">
                <a href="/test.7z">
                <a href="/test.tar">
                <a href="/test.tgz">""",
            ),
        )
        (
            module_test.set_expect_requests(
                dict(uri="/test.zip"),
                dict(
                    response_data=zip_file.read_bytes(),
                    headers={"Content-Type": "application/zip"},
                ),
            ),
        )
        (
            module_test.set_expect_requests(
                dict(uri="/test-zip.zip"),
                dict(
                    response_data=zip_zip_file.read_bytes(),
                    headers={"Content-Type": "application/zip"},
                ),
            ),
        )
        (
            module_test.set_expect_requests(
                dict(uri="/test.bz2"),
                dict(
                    response_data=bz2_file.read_bytes(),
                    headers={"Content-Type": "application/x-bzip2"},
                ),
            ),
        )
        (
            module_test.set_expect_requests(
                dict(uri="/test.xz"),
                dict(
                    response_data=xz_file.read_bytes(),
                    headers={"Content-Type": "application/x-xz"},
                ),
            ),
        )
        (
            module_test.set_expect_requests(
                dict(uri="/test.7z"),
                dict(
                    response_data=zip7_file.read_bytes(),
                    headers={"Content-Type": "application/x-7z-compressed"},
                ),
            ),
        )
        # (
        #     module_test.set_expect_requests(
        #         dict(uri="/test.rar"),
        #         dict(
        #             response_data=b"Rar!\x1a\x07\x01\x003\x92\xb5\xe5\n\x01\x05\x06\x00\x05\x01\x01\x80\x80\x00\xa2N\x8ec&\x02\x03\x0b\x93\x00\x04\x93\x00\xa4\x83\x02\xc9\x11f\x06\x80\x00\x01\x08test.txt\n\x03\x13S\x96ug\x96\xf3\x1b\x06This is a test file\x1dwVQ\x03\x05\x04\x00",
        #             headers={"Content-Type": "application/vnd.rar"},
        #         ),
        #     ),
        # )
        # (
        #     module_test.set_expect_requests(
        #         dict(uri="/test.lzma"),
        #         dict(
        #             response_data=lzma_file.read_bytes(),
        #             headers={"Content-Type": "application/x-lzma"},
        #         ),
        #     ),
        # )
        (
            module_test.set_expect_requests(
                dict(uri="/test.tar"),
                dict(
                    response_data=tar_file.read_bytes(),
                    headers={"Content-Type": "application/x-tar"},
                ),
            ),
        )
        (
            module_test.set_expect_requests(
                dict(uri="/test.tgz"),
                dict(
                    response_data=tgz_file.read_bytes(),
                    headers={"Content-Type": "application/x-tgz"},
                ),
            ),
        )

    def check(self, module_test, events):
        filesystem_events = [e for e in events if e.type == "FILESYSTEM"]

        # ZIP
        zip_file_event = [e for e in filesystem_events if "test.zip" in e.data["path"]]
        assert 1 == len(zip_file_event), "No zip file found"
        file = Path(zip_file_event[0].data["path"])
        assert file.is_file(), f"File not found at {file}"
        extract_event = [e for e in filesystem_events if "test_zip" in e.data["path"] and "folder" in e.tags]
        assert 1 == len(extract_event), "Failed to extract zip"
        extract_path = Path(extract_event[0].data["path"]) / "test.txt"
        assert extract_path.is_file(), "Failed to extract the test file"

        # Recursive ZIP
        zip_zip_file_event = [e for e in filesystem_events if "test-zip.zip" in e.data["path"]]
        assert 1 == len(zip_zip_file_event), "No recursive file found"
        file = Path(zip_zip_file_event[0].data["path"])
        assert file.is_file(), f"File not found at {file}"
        extract_event = [e for e in filesystem_events if "test-zip_zip" in e.data["path"] and "folder" in e.tags]
        assert 1 == len(extract_event), "Failed to extract zip"
        extract_path = Path(extract_event[0].data["path"]) / "test" / "test.txt"
        assert extract_path.is_file(), "Failed to extract the test file"

        # BZ2
        bz2_file_event = [e for e in filesystem_events if "test.bz2" in e.data["path"]]
        assert 1 == len(bz2_file_event), "No bz2 file found"
        file = Path(bz2_file_event[0].data["path"])
        assert file.is_file(), f"File not found at {file}"
        extract_event = [e for e in filesystem_events if "test_bz2" in e.data["path"] and "folder" in e.tags]
        assert 1 == len(extract_event), "Failed to extract bz2"
        extract_path = Path(extract_event[0].data["path"]) / "test.txt"
        assert extract_path.is_file(), "Failed to extract the test file"

        # XZ
        xz_file_event = [e for e in filesystem_events if "test.xz" in e.data["path"]]
        assert 1 == len(xz_file_event), "No xz file found"
        file = Path(xz_file_event[0].data["path"])
        assert file.is_file(), f"File not found at {file}"
        extract_event = [e for e in filesystem_events if "test_xz" in e.data["path"] and "folder" in e.tags]
        assert 1 == len(extract_event), "Failed to extract xz"
        extract_path = Path(extract_event[0].data["path"]) / "test.txt"
        assert extract_path.is_file(), "Failed to extract the test file"

        # 7z
        zip7_file_event = [e for e in filesystem_events if "test.7z" in e.data["path"]]
        assert 1 == len(zip7_file_event), "No 7z file found"
        file = Path(zip7_file_event[0].data["path"])
        assert file.is_file(), f"File not found at {file}"
        extract_event = [e for e in filesystem_events if "test_7z" in e.data["path"] and "folder" in e.tags]
        assert 1 == len(extract_event), "Failed to extract 7z"
        extract_path = Path(extract_event[0].data["path"]) / "test.txt"
        assert extract_path.is_file(), "Failed to extract the test file"

        # RAR
        # rar_file_event = [e for e in filesystem_events if "test.rar" in e.data["path"]]
        # assert 1 == len(rar_file_event), "No rar file found"
        # file = Path(rar_file_event[0].data["path"])
        # assert file.is_file(), f"File not found at {file}"
        # extract_event = [e for e in filesystem_events if "test_rar" in e.data["path"] and "folder" in e.tags]
        # assert 1 == len(extract_event), "Failed to extract rar"
        # extract_path = Path(extract_event[0].data["path"]) / "test.txt"
        # assert extract_path.is_file(), list(extract_path.parent.iterdir())

        # LZMA
        # lzma_file_event = [e for e in filesystem_events if "test.lzma" in e.data["path"]]
        # assert 1 == len(lzma_file_event), "No lzma file found"
        # file = Path(lzma_file_event[0].data["path"])
        # assert file.is_file(), f"File not found at {file}"
        # extract_event = [e for e in filesystem_events if "test_lzma" in e.data["path"] and "folder" in e.tags]
        # assert 1 == len(extract_event), "Failed to extract lzma"
        # extract_path = Path(extract_event[0].data["path"]) / "test.txt"
        # assert extract_path.is_file(), "Failed to extract the test file"

        # TAR
        tar_file_event = [e for e in filesystem_events if "test.tar" in e.data["path"]]
        assert 1 == len(tar_file_event), "No tar file found"
        file = Path(tar_file_event[0].data["path"])
        assert file.is_file(), f"File not found at {file}"
        extract_event = [e for e in filesystem_events if "test_tar" in e.data["path"] and "folder" in e.tags]
        assert 1 == len(extract_event), "Failed to extract tar"
        extract_path = Path(extract_event[0].data["path"]) / "test.txt"
        assert extract_path.is_file(), "Failed to extract the test file"

        # TGZ
        tgz_file_event = [e for e in filesystem_events if "test.tgz" in e.data["path"]]
        assert 1 == len(tgz_file_event), "No tgz file found"
        file = Path(tgz_file_event[0].data["path"])
        assert file.is_file(), f"File not found at {file}"
        extract_event = [e for e in filesystem_events if "test_tgz" in e.data["path"] and "folder" in e.tags]
        assert 1 == len(extract_event), "Failed to extract tgz"
        extract_path = Path(extract_event[0].data["path"]) / "test.txt"
        assert extract_path.is_file(), "Failed to extract the test file"


class TestUnarchiveTraversalCheck(ModuleTestBase):
    modules_overrides = ["unarchive"]

    async def setup_after_prep(self, module_test):
        m = module_test.scan.modules["unarchive"]
        temp_path = Path(BBOT_TEST_DIR)
        temp_path.mkdir(exist_ok=True)

        # safe tar
        safe_tar = temp_path / "safe.tar"
        with tarfile.open(safe_tar, "w") as tar:
            data = b"safe content"
            info = tarfile.TarInfo(name="subdir/normal.txt")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))

        # tar with ../ traversal
        traversal_tar = temp_path / "traversal.tar"
        with tarfile.open(traversal_tar, "w") as tar:
            data = b"escaped"
            info = tarfile.TarInfo(name="../../../tmp/escaped.txt")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))

        # tar with absolute path
        absolute_tar = temp_path / "absolute.tar"
        with tarfile.open(absolute_tar, "w") as tar:
            data = b"absolute"
            info = tarfile.TarInfo(name="/etc/cron.d/evil")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))

        # safe zip
        safe_zip = temp_path / "safe.zip"
        with zipfile.ZipFile(safe_zip, "w") as zf:
            zf.writestr("normal.txt", "safe content")

        # zip with ../ traversal
        traversal_zip = temp_path / "traversal.zip"
        with zipfile.ZipFile(traversal_zip, "w") as zf:
            zf.writestr("../escaped.txt", "escaped")

        # tar with symlink entry
        symlink_tar = temp_path / "symlink.tar"
        with tarfile.open(symlink_tar, "w") as tar:
            info = tarfile.TarInfo(name="evil_link")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            tar.addfile(info)

        # zip with symlink entry (unix symlink stored via external_attr)
        symlink_zip = temp_path / "symlink.zip"
        symlink_info = zipfile.ZipInfo("evil_link")
        symlink_info.create_system = 3  # unix
        symlink_info.external_attr = 0o120777 << 16  # S_IFLNK | 0o777
        with zipfile.ZipFile(symlink_zip, "w") as zf:
            zf.writestr(symlink_info, "/etc/passwd")

        # 7z-native symlink stored as a link (-snl). A plain unix-symlink zip lists
        # as " lrwxrwxrwx" on mainline 7-Zip, which the pre-fix guard already caught,
        # so the zip case only exercises the fix on p7zip. A 7z-native symlink lists
        # with a leading DOS-attribute token ("A lrwxrwxrwx") that the pre-fix guard
        # missed, so this exercises the fixed mode-field check on mainline 7-Zip too.
        symlink_7z = temp_path / "symlink.7z"
        link_src = temp_path / "link_src"
        link_src.unlink(missing_ok=True)
        link_src.symlink_to("/etc/passwd")
        add_proc = await asyncio.create_subprocess_exec(
            "7z",
            "a",
            "-snl",
            "symlink.7z",
            "link_src",
            cwd=str(temp_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await add_proc.communicate()
        list_proc = await asyncio.create_subprocess_exec(
            "7z",
            "l",
            "-slt",
            str(symlink_7z),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        list_out, _ = await list_proc.communicate()

        self.results = {}
        self.results["safe_tar"] = await m._check_archive_safe(safe_tar, "tar")
        self.results["traversal_tar"] = await m._check_archive_safe(traversal_tar, "tar")
        self.results["absolute_tar"] = await m._check_archive_safe(absolute_tar, "tar")
        self.results["safe_zip"] = await m._check_archive_safe(safe_zip, "zip")
        self.results["traversal_zip"] = await m._check_archive_safe(traversal_zip, "zip")
        self.results["symlink_tar"] = await m._check_archive_safe(symlink_tar, "tar")
        self.results["symlink_zip"] = await m._check_archive_safe(symlink_zip, "zip")
        # only meaningful if 7z actually stored a link (needs -snl support)
        self.results["symlink_7z_is_link"] = b"lrwx" in list_out
        self.results["symlink_7z"] = await m._check_archive_safe(symlink_7z, "7z")

    def check(self, module_test, events):
        assert self.results["safe_tar"], "Safe tar rejected"
        assert not self.results["traversal_tar"], "Traversal tar was not rejected"
        assert not self.results["absolute_tar"], "Absolute path tar was not rejected"
        assert self.results["safe_zip"], "Safe zip rejected"
        assert not self.results["traversal_zip"], "Traversal zip was not rejected"
        assert not self.results["symlink_tar"], "Symlink tar was not rejected"
        assert not self.results["symlink_zip"], "Symlink zip was not rejected"
        # 7z-native symlinks list with a DOS-attribute prefix ("A lrwxrwxrwx") that
        # the pre-fix guard missed; assert only when the link was actually stored
        # (mainline 7-Zip always does, which is exactly where the zip case is a no-op)
        if self.results["symlink_7z_is_link"]:
            assert not self.results["symlink_7z"], "Symlink 7z was not rejected"
