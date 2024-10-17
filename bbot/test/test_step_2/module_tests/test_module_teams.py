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
                    status_code=400,
                    json={
                        "error": {
                            "code": "WorkflowTriggerIsNotEnabled",
                            "message": "Could not execute workflow 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' trigger 'manual' with state 'Disabled': trigger is not enabled.",
                        }
                    },
                )
            else:
                return httpx.Response(status_code=200)

        module_test.httpx_mock.add_callback(custom_response, url=self.webhook_url)
