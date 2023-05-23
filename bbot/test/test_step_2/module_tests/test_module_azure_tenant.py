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

    async def setup_after_prep(self, module_test):
        module_test.httpx_mock.add_response(
            method="POST",
            url="https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc",
            text=self.tenant_response,
        )

    def check(self, module_test, events):
        assert any(e.data == "blacklanternsecurity.onmicrosoft.com" and "affiliate" in e.tags for e in events)
