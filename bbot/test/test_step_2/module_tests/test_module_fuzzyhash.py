from .base import ModuleTestBase
import base64

class Testfuzzy_image_hash(ModuleTestBase):
    targets = [
        "http://127.0.0.1:8888/"
    ]

    sample_page = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Image Link Example</title>
        </head>
        <body>
            <img src="testimage.png" alt="Test Image">
        </body>
        </html>
    """

    testimage = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAACklEQVR4nGMAAQAABQABDQottAAAAABJRU5ErkJggg=="
    config_overrides = {
        "modules": {
            "fuzzy_image_hash": {
                "fuzzy_hashes": "3:yionv//thPlE+tnM1AsGlk4hvM/jp:6v/lhPfZMWn+4hvsjp",
            }
        }
    }
    modules_overrides = ["fuzzy_image_hash", "httpx"]

    async def setup_after_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": self.sample_page}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/testimage.png"}
        respond_args = {"response_data": base64.b64decode(self.testimage)}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        validHash = False
        for e in events:
            if (
                e.type == "FINDING"
                and "Identified matched similar score above"
                and "3:yionv//thPlE+tnM1AsGlk4hvM/jp:6v/lhPfZMWn+4hvsjp"
                in e.data["description"]
                ):
                    validHash = True
        assert validHash, "Invalid Hash"