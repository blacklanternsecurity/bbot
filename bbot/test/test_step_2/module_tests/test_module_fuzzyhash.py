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

    async def setup_before_prep(self, module_test):
        # Add a response to the httpx_mock to return the image content when the image URL is requested.
        module_test.httpx_mock.add_response(
            method="GET",
            url="/",
            content=self.sample_page
        )

        module_test.httpx_mock.add_response(
            method="GET",
            url="/testimage.png",
            content=base64.b64decode(self.testimage)
        )

    async def check(self, module_test, events):
        validHash = False
        for e in events:
            print(e)
            if (
                e.type == "FINDING"
                and "Identified matched similar score above"
                and "3:yionv//thPlE+tnM1AsGlk4hvM/jp:6v/lhPfZMWn+4hvsjp"
                in e.data["description"]
                ):
                    print(e.data["desecription"])
                    validHash = True
        assert validHash, "Invalid Hash"
        assert 1==2, "Test fail"