from .base import ModuleTestBase


class TestAzure_Tenant(ModuleTestBase):
    tenant_response = """
<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:a="http://www.w3.org/2005/08/addressing">
  <s:Header>
    <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformationResponse</a:Action>
    <h:ServerVersionInfo xmlns:h="http://schemas.microsoft.com/exchange/2010/Autodiscover" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
      <h:MajorVersion>15</h:MajorVersion>
      <h:MinorVersion>20</h:MinorVersion>
      <h:MajorBuildNumber>6411</h:MajorBuildNumber>
      <h:MinorBuildNumber>14</h:MinorBuildNumber>
      <h:Version>Exchange2015</h:Version>
    </h:ServerVersionInfo>
  </s:Header>
  <s:Body>
    <GetFederationInformationResponseMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
      <Response xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
        <ErrorCode>NoError</ErrorCode>
        <ErrorMessage/>
        <ApplicationUri>outlook.com</ApplicationUri>
        <Domains>
          <Domain>blacklanternsecurity.onmicrosoft.com</Domain>
        </Domains>
        <TokenIssuers>
          <TokenIssuer>
            <Endpoint>https://login.microsoftonline.com/extSTS.srf</Endpoint>
            <Uri>urn:federation:MicrosoftOnline</Uri>
          </TokenIssuer>
        </TokenIssuers>
      </Response>
    </GetFederationInformationResponseMessage>
  </s:Body>
</s:Envelope>"""

    openid_config_azure = {
        "token_endpoint": "https://login.windows.net/cc74fc12-4142-400e-a653-f98bdeadbeef/oauth2/token",
        "token_endpoint_auth_methods_supported": ["client_secret_post", "private_key_jwt", "client_secret_basic"],
        "jwks_uri": "https://login.windows.net/common/discovery/keys",
        "response_modes_supported": ["query", "fragment", "form_post"],
        "subject_types_supported": ["pairwise"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "response_types_supported": ["code", "id_token", "code id_token", "token id_token", "token"],
        "scopes_supported": ["openid"],
        "issuer": "https://sts.windows.net/cc74fc12-4142-400e-a653-f98bdeadbeef/",
        "microsoft_multi_refresh_token": True,
        "authorization_endpoint": "https://login.windows.net/cc74fc12-4142-400e-a653-f98bdeadbeef/oauth2/authorize",
        "device_authorization_endpoint": "https://login.windows.net/cc74fc12-4142-400e-a653-f98bdeadbeef/oauth2/devicecode",
        "http_logout_supported": True,
        "frontchannel_logout_supported": True,
        "end_session_endpoint": "https://login.windows.net/cc74fc12-4142-400e-a653-f98bdeadbeef/oauth2/logout",
        "claims_supported": [
            "sub",
            "iss",
            "cloud_instance_name",
            "cloud_instance_host_name",
            "cloud_graph_host_name",
            "msgraph_host",
            "aud",
            "exp",
            "iat",
            "auth_time",
            "acr",
            "amr",
            "nonce",
            "email",
            "given_name",
            "family_name",
            "nickname",
        ],
        "check_session_iframe": "https://login.windows.net/cc74fc12-4142-400e-a653-f98bdeadbeef/oauth2/checksession",
        "userinfo_endpoint": "https://login.windows.net/cc74fc12-4142-400e-a653-f98bdeadbeef/openid/userinfo",
        "kerberos_endpoint": "https://login.windows.net/cc74fc12-4142-400e-a653-f98bdeadbeef/kerberos",
        "tenant_region_scope": "NA",
        "cloud_instance_name": "microsoftonline.com",
        "cloud_graph_host_name": "graph.windows.net",
        "msgraph_host": "graph.microsoft.com",
        "rbac_url": "https://pas.windows.net",
    }

    async def setup_after_prep(self, module_test):
        module_test.httpx_mock.add_response(
            method="POST",
            url="https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc",
            text=self.tenant_response,
        )
        module_test.httpx_mock.add_response(
            url="https://login.windows.net/blacklanternsecurity.com/.well-known/openid-configuration",
            json=self.openid_config_azure,
        )

    def check(self, module_test, events):
        assert any(
            e.type.startswith("DNS_NAME")
            and e.data == "blacklanternsecurity.onmicrosoft.com"
            and "affiliate" in e.tags
            for e in events
        )
        assert any(
            e.type == "AZURE_TENANT"
            and e.data["tenant-id"] == "cc74fc12-4142-400e-a653-f98bdeadbeef"
            and "blacklanternsecurity.onmicrosoft.com" in e.data["domains"]
            and "blacklanternsecurity" in e.data["tenant-names"]
            for e in events
        )
