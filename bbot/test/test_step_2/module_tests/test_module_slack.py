from .test_module_discord import TestDiscord as DiscordBase


class TestSlack(DiscordBase):
    modules_overrides = ["slack", "excavate", "badsecrets", "http"]
    webhook_url = "https://hooks.slack.com/services/deadbeef/deadbeef/deadbeef"
    config_overrides = {"modules": {"slack": {"webhook_url": webhook_url, "min_severity": "INFO"}}}
