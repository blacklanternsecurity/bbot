from pathlib import Path
from .base import ModuleTestBase
from bbot.test.bbot_fixtures import bbot_test_dir


class TestGitDumper_Dirlisting(ModuleTestBase):
    targets = [
        "http://127.0.0.1:8888/test",
    ]

    modules_overrides = ["git", "gitdumper", "httpx"]
    config_overrides = {"modules": {"gitdumper": {"output_folder": str(bbot_test_dir / "test_output")}}}

    index_html = """<html>
        <head>
            <title>Index of /.git</title>
        </head>
        <body>
            <h1>Index of /.git</h1>
            <table>
                <tr><th>Name</th><th>Size</th></tr>
                <tr><td><a href='/test/.git/branches/'>&lt;branches&gt;</a></td><td></td></tr>
                <tr><td><a href='/test/.git/COMMIT_EDITMSG'>COMMIT_EDITMSG</a></td><td>157B</td></tr>
                <tr><td><a href='/test/.git/config'>config</a></td><td>157B</td></tr>
                <tr><td><a href='/test/.git/description'>description</a></td><td>73B</td></tr>
                <tr><td><a href='/test/.git/HEAD'>HEAD</a></td><td>23B</td></tr>
                <tr><td><a href='/test/.git/hooks/'>&lt;hooks&gt;</a></td><td></td></tr>
                <tr><td><a href='/test/.git/info/'>&lt;info&gt;</a></td><td></td></tr>
                <tr><td><a href='/test/.git/objects/'>&lt;objects&gt;</a></td><td></td></tr>
                <tr><td><a href='/test/.git/index'>index</a></td><td></td></tr>
                <tr><td><a href='/test/.git/refs/'>&lt;refs&gt;</a></td><td></td></tr>
                <tr><td><a href='/test/.git/logs/'>&lt;logs&gt;</a></td><td></td></tr>
            </table>
        </body>
    </html>"""

    info_index = """<html>
        <head>
            <title>Index of /.git/info</title>
        </head>
        <body>
            <h1>Index of /.git/info</h1>
            <table>
                <tr><th>Name</th><th>Size</th></tr>
                <tr><td><a href='../'>[..]</a></td><td></td></tr>
                <tr><td><a href='/test/.git/info/exclude'>exclude</a></td><td>240B</td></tr>
                <tr><td><a href='http://exclude.com/excludeme'>excludeme</a></td><td>0B</td></tr>
            </table>
        </body>
    </html>"""

    objects_index = """<html>
        <head>
            <title>Index of /.git/objects</title>
        </head>
        <body>
            <h1>Index of /.git/objects</h1>
            <table>
                <tr><th>Name</th><th>Size</th></tr>
                <tr><td><a href='../'>[..]</a></td><td></td></tr>
                <tr><td><a href='/test/.git/objects/05/'>&lt;05&gt;</a></td><td></td></tr>
                <tr><td><a href='/test/.git/objects/34/'>&lt;34&gt;</a></td><td></td></tr>
                <tr><td><a href='/test/.git/objects/c2/'>&lt;c2&gt;</a></td><td></td></tr>
                <tr><td><a href='/test/.git/objects/pack/'>&lt;pack&gt;</a></td><td></td></tr>
                <tr><td><a href='/test/.git/objects/info/'>&lt;info&gt;</a></td><td></td></tr>
            </table>
        </body>
    </html>"""

    objects_o5_index = """<html>
        <head>
            <title>Index of /.git/objects/05</title>
        </head>
        <body>
            <h1>Index of /.git/objects/05</h1>
            <table>
                <tr><th>Name</th><th>Size</th></tr>
                <tr><td><a href='../'>[..]</a></td><td></td></tr>
                <tr><td><a href='/test/.git/objects/05/27e6bd2d76b45e2933183f1b506c7ac49f5872'>27e6bd2d76b45e2933183f1b506c7ac49f5872</a></td><td></td></tr>
            </table>
        </body>
    </html>"""

    objects_34_index = """<html>
        <head>
            <title>Index of /.git/objects/34</title>
        </head>
        <body>
            <h1>Index of /.git/objects/34</h1>
            <table>
                <tr><th>Name</th><th>Size</th></tr>
                <tr><td><a href='../'>[..]</a></td><td></td></tr>
                <tr><td><a href='/test/.git/objects/34/dc86f0247798892a89553e7c5c2d5aa06c2c5b'>dc86f0247798892a89553e7c5c2d5aa06c2c5b</a></td><td></td></tr>
            </table>
        </body>
    </html>"""

    objects_c2_index = """<html>
        <head>
            <title>Index of /.git/objects/c2</title>
        </head>
        <body>
            <h1>Index of /.git/objects/c2</h1>
            <table>
                <tr><th>Name</th><th>Size</th></tr>
                <tr><td><a href='../'>[..]</a></td><td></td></tr>
                <tr><td><a href='/test/.git/objects/c2/69d751b8e2fd0be0d0dc7a6437a4dce4ec0200'>69d751b8e2fd0be0d0dc7a6437a4dce4ec0200</a></td><td></td></tr>
            </table>
        </body>
    </html>"""

    refs_index = """<html>
        <head>
            <title>Index of /.git/refs</title>
        </head>
        <body>
            <h1>Index of /.git/refs</h1>
            <table>
                <tr><th>Name</th><th>Size</th></tr>
                <tr><td><a href='../'>[..]</a></td><td></td></tr>
                <tr><td><a href='/test/.git/refs/heads/'>&lt;heads&gt;</a></td><td></td></tr>
                <tr><td><a href='/test/.git/refs/tags/'>&lt;tags&gt;</a></td><td></td></tr>
            </table>
        </body>
    </html>
    """

    refs_heads_index = """<html>
        <head>
            <title>Index of /.git/refs/heads</title>
        </head>
        <body>
            <h1>Index of /.git/refs/heads</h1>
            <table>
                <tr><th>Name</th><th>Size</th></tr>
                <tr><td><a href='../'>[..]</a></td><td></td></tr>
                <tr><td><a href='/test/.git/refs/heads/master'>master</a></td><td></td></tr>
            </table>
        </body>
    </html>
    """

    logs_index = """<html>
        <head>
            <title>Index of /.git/logs</title>
        </head>
        <body>
            <h1>Index of /.git/logs</h1>
            <table>
                <tr><th>Name</th><th>Size</th></tr>
                <tr><td><a href='../'>[..]</a></td><td></td></tr>
                <tr><td><a href='/test/.git/logs/HEAD'>HEAD</a></td><td></td></tr>
                <tr><td><a href='/test/.git/logs/refs/'>&lt;tags&gt;</a></td><td></td></tr>
            </table>
        </body>
    </html>
    """

    logs_refs_index = """<html>
        <head>
            <title>Index of /.git/logs/refs</title>
        </head>
        <body>
            <h1>Index of /.git/logs/refs</h1>
            <table>
                <tr><th>Name</th><th>Size</th></tr>
                <tr><td><a href='../'>[..]</a></td><td></td></tr>
                <tr><td><a href='/test/.git/logs/refs/heads/'>&lt;heads&gt;</a></td><td></td></tr>
            </table>
        </body>
    </html>
    """

    logs_refs_heads_index = """<html>
        <head>
            <title>Index of /.git/logs/refs/heads</title>
        </head>
        <body>
            <h1>Index of /.git/logs/refs/heads</h1>
            <table>
                <tr><th>Name</th><th>Size</th></tr>
                <tr><td><a href='../'>[..]</a></td><td></td></tr>
                <tr><td><a href='/test/.git/logs/refs/heads/master'>master</a></td><td></td></tr>
            </table>
        </body>
    </html>
    """

    empty_index = """<html>
        <head>
            <title>Index of /.git/...</title>
        </head>
        <body>
            <h1>Index of /.git/...</h1>
            <table>
                <tr><th>Name</th><th>Size</th></tr>
                <tr><td><a href='../'>[..]</a></td><td></td></tr>
            </table>
        </body>
    </html>"""

    git_head = "ref: refs/heads/master"

    refs_head = "34dc86f0247798892a89553e7c5c2d5aa06c2c5b"

    logs_head = "0000000000000000000000000000000000000000 34dc86f0247798892a89553e7c5c2d5aa06c2c5b Test <test@test.com> 1738516534 +0000	commit (initial): Initial commit"

    logs_master_head = "0000000000000000000000000000000000000000 34dc86f0247798892a89553e7c5c2d5aa06c2c5b Test <test@test.com> 1738516534 +0000	commit (initial): Initial commit"

    git_description = "Unnamed repository; edit this file 'description' to name the repository."

    git_commit_editmsg = "Initial commit"

    git_config = """[core]
    repositoryformatversion = 0
    filemode = true
    bare = false
    logallrefupdates = true"""

    git_exclude = """# git ls-files --others --exclude-from=.git/info/exclude
    # Lines that start with '#' are comments.
    # For a project mostly in C, the following would be a good set of
    # exclude patterns (uncomment them if you want to use them):
    # *.[oa]
    # *~"""

    filebytes_gitindex = b"DIRC\x00\x00\x00\x02\x00\x00\x00\x01g\x9f\xbe\x04\x14\xfcb\xd1g\x9f\xbe\x04\x14\xfcb\xd1\x00\x00\x08 \x00\x04aD\x00\x00\x81\xa4\x00\x00\x03\xe8\x00\x00\x03\xe8\x00\x00\x00\x0f\x05'\xe6\xbd-v\xb4^)3\x18?\x1bPlz\xc4\x9fXr\x00\x08test.txt\x00\x00TREE\x00\x00\x00\x19\x001 0\n\xc2i\xd7Q\xb8\xe2\xfd\x0b\xe0\xd0\xdczd7\xa4\xdc\xe4\xec\x02\x00\xe8m|iw\xbb\xd6\x88;f\xdbW\x10yY\xd2\xb0G\xcfJ"
    filebytes_27e6bd2d76b45e2933183f1b506c7ac49f5872 = (
        b"x\x01K\xca\xc9OR04e\x08\xc9\xc8,V\x00\xa2D\x85\x92\xd4\xe2\x12.\x00U\xab\x07%"
    )
    filebytes_dc86f0247798892a89553e7c5c2d5aa06c2c5b = b"x\x01\x9d\x8dK\n\x021\x10D]\xe7\x14\xbd\x17\x86\xce?\x82\x88\x0b7\x9e\xc0u\xa6\xd3:\x81\xc4\xc0\x18\x99\xeb\x1b\x98\x1bX\xbbzP\xaf\xa8\xd5\x9a;\xc8\xa0\x0f}e\x06R\xee\x94\xbc\x95s`\xf5L83&L\xe4\xa33\xdaG\x93\x88\r\x13*D\x11\xbf}i+\xdcZ\x85\xc7\xc2\x1b\x97\x02\xe7\xd4\xea\xb4\xed\xe5\xfa\x89/\x9e\xa8\xd5\x0bH\xaf\x83\x95\xcej\x03G\x1c\x11\x83\x8e\xcf\xce\xff\xad\xc5\xfd\x9d{\x8e\x05v\x8d\xf8\x01\xfaF<\x05"
    filebytes_69d751b8e2fd0be0d0dc7a6437a4dce4ec0200 = b"x\x01+)JMU06c040031Q(I-.\xd1+\xa9(a`U\x7f\xb6W\xb7lK\x9c\xa6\xb1\x84\xbdt@N\xd5\x91\xf9\x11E\x00*\x05\x0e\x8c"

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/"}, respond_args={"response_data": self.index_html}
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/index"}, respond_args={"response_data": self.filebytes_gitindex}
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/COMMIT_EDITMSG"}, respond_args={"response_data": self.git_commit_editmsg}
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/config"}, respond_args={"response_data": self.git_config}
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/branches/"}, respond_args={"response_data": self.empty_index}
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/description"}, respond_args={"response_data": self.git_description}
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/HEAD"}, respond_args={"response_data": self.git_head}
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/hooks/"}, respond_args={"response_data": self.empty_index}
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/info/"}, respond_args={"response_data": self.info_index}
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/info/exclude"}, respond_args={"response_data": self.git_exclude}
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/objects/"}, respond_args={"response_data": self.objects_index}
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/objects/05/"}, respond_args={"response_data": self.objects_o5_index}
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/objects/05/27e6bd2d76b45e2933183f1b506c7ac49f5872"},
            respond_args={"response_data": self.filebytes_27e6bd2d76b45e2933183f1b506c7ac49f5872},
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/objects/34/"}, respond_args={"response_data": self.objects_34_index}
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/objects/34/dc86f0247798892a89553e7c5c2d5aa06c2c5b"},
            respond_args={"response_data": self.filebytes_dc86f0247798892a89553e7c5c2d5aa06c2c5b},
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/objects/c2/"}, respond_args={"response_data": self.objects_c2_index}
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/objects/c2/69d751b8e2fd0be0d0dc7a6437a4dce4ec0200"},
            respond_args={"response_data": self.filebytes_69d751b8e2fd0be0d0dc7a6437a4dce4ec0200},
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/objects/info/"}, respond_args={"response_data": self.empty_index}
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/objects/pack/"}, respond_args={"response_data": self.empty_index}
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/refs/"}, respond_args={"response_data": self.refs_index}
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/refs/heads/"}, respond_args={"response_data": self.refs_heads_index}
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/refs/heads/master"}, respond_args={"response_data": self.refs_head}
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/refs/tags/"}, respond_args={"response_data": self.empty_index}
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/logs/"}, respond_args={"response_data": self.logs_index}
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/logs/refs/"}, respond_args={"response_data": self.logs_refs_index}
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/logs/refs/heads/"},
            respond_args={"response_data": self.logs_refs_heads_index},
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/logs/refs/heads/master"},
            respond_args={"response_data": self.logs_master_head},
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/logs/HEAD"}, respond_args={"response_data": self.logs_head}
        )

    def check(self, module_test, events):
        assert any(
            e.type == "CODE_REPOSITORY"
            and "git-directory" in e.tags
            and e.data["url"] == "http://127.0.0.1:8888/test/.git/"
            for e in events
        )
        filesystem_events = [
            e
            for e in events
            if e.type == "FILESYSTEM" and "http-127-0-0-1-8888-test-git" in e.data["path"] and "git" in e.tags
        ]
        assert 1 == len(filesystem_events), "Failed to git clone CODE_REPOSITORY"
        filesystem_event = filesystem_events[0]
        folder = Path(filesystem_event.data["path"])
        assert folder.is_dir(), "Destination folder doesn't exist"
        with open(folder / "test.txt") as f:
            content = f.read()
            assert content == "This is a test\n", "File content doesn't match"


class TestGitDumper_NoDirlisting(TestGitDumper_Dirlisting):
    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/index"}, respond_args={"response_data": self.filebytes_gitindex}
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/COMMIT_EDITMSG"}, respond_args={"response_data": self.git_commit_editmsg}
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/config"}, respond_args={"response_data": self.git_config}
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/description"}, respond_args={"response_data": self.git_description}
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/HEAD"}, respond_args={"response_data": self.git_head}
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/info/exclude"}, respond_args={"response_data": self.git_exclude}
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/objects/05/27e6bd2d76b45e2933183f1b506c7ac49f5872"},
            respond_args={"response_data": self.filebytes_27e6bd2d76b45e2933183f1b506c7ac49f5872},
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/objects/34/dc86f0247798892a89553e7c5c2d5aa06c2c5b"},
            respond_args={"response_data": self.filebytes_dc86f0247798892a89553e7c5c2d5aa06c2c5b},
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/objects/c2/69d751b8e2fd0be0d0dc7a6437a4dce4ec0200"},
            respond_args={"response_data": self.filebytes_69d751b8e2fd0be0d0dc7a6437a4dce4ec0200},
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/refs/heads/master"}, respond_args={"response_data": self.refs_head}
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/logs/refs/heads/master"},
            respond_args={"response_data": self.logs_master_head},
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/logs/HEAD"}, respond_args={"response_data": self.logs_head}
        )
