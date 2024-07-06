import httpx

from .test_module_discord import TestDiscord as DiscordBase


class TestTeams(DiscordBase):
    modules_overrides = ["teams", "excavate", "badsecrets", "httpx"]

    webhook_url = "https://evilcorp.webhook.office.com/webhookb2/deadbeef@deadbeef/IncomingWebhook/deadbeef/deadbeef"
    config_overrides = {"modules": {"teams": {"webhook_url": webhook_url}}}

    async def setup_after_prep(self, module_test):
        self.custom_setup(module_test)

        def custom_response(request: httpx.Request):
            module_test.request_count += 1
            if module_test.request_count == 2:
                return httpx.Response(
                    status_code=200,
                    text="Webhook message delivery failed with error: Microsoft Teams endpoint returned HTTP error 429 with ContextId tcid=0,server=msgapi-production-eus-azsc2-4-170,cv=deadbeef=2..",
                )
            else:
                return httpx.Response(
                    status_code=200,
                    text="1",
                )

        module_test.httpx_mock.add_callback(custom_response, url=self.webhook_url)
