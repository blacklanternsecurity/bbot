import asyncio

from pathlib import Path
from .base import ModuleTestBase

from ...bbot_fixtures import *


class TestUnarchive(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["filedownload", "httpx", "excavate", "speculate", "unarchive"]
    config_overrides = {
        "modules": {
            "filedownload": {
                "output_folder": bbot_test_dir / "filedownload",
            },
        }
    }

    async def setup_after_prep(self, module_test):
        temp_path = Path("/tmp/.bbot_test")

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
            ("7z", "a", '-p""', "-aoa", f"{zip_file}", f"{text_file}"),
            ("7z", "a", '-p""', "-aoa", f"{zip_zip_file}", f"{zip_file}"),
            ("tar", "-C", f"{temp_path}", "-cvjf", f"{bz2_file}", f"{text_file.name}"),
            ("tar", "-C", f"{temp_path}", "-cvJf", f"{xz_file}", f"{text_file.name}"),
            ("7z", "a", '-p""', "-aoa", f"{zip7_file}", f"{text_file}"),
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
