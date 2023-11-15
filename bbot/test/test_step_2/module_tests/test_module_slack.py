from .test_module_discord import TestDiscord as DiscordBase


class TestSlack(DiscordBase):
    targets = ["http://127.0.0.1:8888/cookie.aspx", "http://127.0.0.1:8888/cookie2.aspx"]
    modules_overrides = ["slack", "excavate", "badsecrets", "httpx"]

    webhook_url = "https://hooks.slack.com/services/deadbeef/deadbeef/deadbeef"
    config_overrides = {"output_modules": {"slack": {"webhook_url": webhook_url}}}
