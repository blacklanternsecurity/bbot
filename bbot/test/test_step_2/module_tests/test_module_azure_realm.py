from .base import ModuleTestBase


class TestAzure_Realm(ModuleTestBase):
    targets = ["evilcorp.com"]
    config_overrides = {"scope": {"report_distance": 1}}

    response_json = {
        "State": 3,
        "UserState": 2,
        "Login": "test@evilcorp.com",
        "NameSpaceType": "Federated",
        "DomainName": "evilcorp.com",
        "FederationGlobalVersion": -1,
        "AuthURL": "https://evilcorp.okta.com/app/office365/deadbeef/sso/wsfed/passive?username=test%40evilcorp.com&wa=wsignin1.0&wtrevilcorplm=urn%3afederation%3aMicrosoftOnline&wctx=",
        "FederationBrandName": "EvilCorp",
        "AuthNForwardType": 1,
        "CloudInstanceName": "microsoftonline.com",
        "CloudInstanceIssuerUri": "urn:federation:MicrosoftOnline",
    }

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns({"evilcorp.com": {"A": ["127.0.0.5"]}})
        module_test.httpx_mock.add_response(
            url="https://login.microsoftonline.com/getuserrealm.srf?login=test@evilcorp.com",
            json=self.response_json,
        )

    def check(self, module_test, events):
        assert any(e.data == "https://evilcorp.okta.com/app/office365/deadbeef/sso/wsfed/passive" for e in events), (
            "Failed to detect URL"
        )
