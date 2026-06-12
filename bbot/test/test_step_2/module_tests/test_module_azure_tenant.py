from .base import ModuleTestBase


class AzureTenantTestBase(ModuleTestBase):
    """Base class for Azure Tenant tests with common setup"""

    modules = ["azure_tenant"]
    targets = ["blacklanternsecurity.com"]

    # Override these in subclasses to customize behavior
    include_onmicrosoft = False
    desktop_sso_enabled = False
    certificate_auth_enabled = False
    cloud_type = None  # None, "dod", "gcc-high"
    federation_url = None
    exchange_online = False
    directory_sync_enabled = False

    async def setup_after_prep(self, module_test):
        # Build email domains
        email_domains = ["blacklanternsecurity.com"]
        if self.include_onmicrosoft:
            email_domains.append("blacklanternsecurity.onmicrosoft.com")

        # Mock azmap.dev response
        module_test.blasthttp_mock.add_response(
            url="https://azmap.dev/api/tenant?domain=blacklanternsecurity.com&extract=true",
            json={
                "tenant_id": "test-tenant-id",
                "tenant_name": "blacklanternsecurity",
                "email_domains": email_domains,
            },
        )

        # Mock ODC endpoint
        module_test.blasthttp_mock.add_response(
            url="https://odc.officeapps.live.com/odc/v2.1/federationprovider?domain=blacklanternsecurity.com",
            json={},
        )

        # Mock OpenID configuration
        openid_config = {}
        if self.cloud_type == "dod":
            openid_config = {
                "tenant_region_scope": "DOD",
                "tenant_region_sub_scope": "DOD",
                "cloud_instance_name": "login.microsoftonline.us",
            }
        elif self.cloud_type == "gcc-high":
            openid_config = {
                "tenant_region_scope": "DODCON",
                "tenant_region_sub_scope": "DODCON",
                "cloud_instance_name": "login.microsoftonline.us",
            }

        module_test.blasthttp_mock.add_response(
            url="https://login.microsoftonline.com/blacklanternsecurity.com/.well-known/openid-configuration",
            json=openid_config,
        )

        # Mock GetCredentialType
        getcred_response = {"EstsProperties": {}, "Credentials": {}}
        if self.desktop_sso_enabled:
            getcred_response["EstsProperties"]["DesktopSsoEnabled"] = True
        if self.certificate_auth_enabled:
            getcred_response["Credentials"]["HasCertAuth"] = True
        if self.federation_url:
            getcred_response["Credentials"]["FederationRedirectUrl"] = self.federation_url

        module_test.blasthttp_mock.add_response(
            url="https://login.microsoftonline.com/common/GetCredentialType",
            method="POST",
            json=getcred_response,
        )

        # Mock UserRealm v2.0
        module_test.blasthttp_mock.add_response(
            url="https://login.microsoftonline.com/common/userrealm/test@blacklanternsecurity.com?api-version=2.0",
            json={},
        )

        # Mock MTA-STS
        if self.exchange_online:
            module_test.blasthttp_mock.add_response(
                url="https://mta-sts.blacklanternsecurity.com/.well-known/mta-sts.txt",
                text="version: STSv1\nmode: enforce\nmx: blacklanternsecurity-com.mail.protection.outlook.com\nmax_age: 604800",
            )
        else:
            module_test.blasthttp_mock.add_response(
                url="https://mta-sts.blacklanternsecurity.com/.well-known/mta-sts.txt",
                status_code=404,
            )

        # Mock Directory Sync check if needed
        if self.include_onmicrosoft:
            sync_result = 0 if self.directory_sync_enabled else 1
            module_test.blasthttp_mock.add_response(
                url="https://login.microsoftonline.com/common/GetCredentialType",
                method="POST",
                json={"IfExistsResult": sync_result},
            )


class TestAzure_Tenant(AzureTenantTestBase):
    """Test basic Azure tenant enumeration"""

    include_onmicrosoft = True

    tenant_response = {
        "tenant_id": "cc74fc12-4142-400e-a653-f98bdeadbeef",
        "tenant_name": "blacklanternsecurity",
        "domain": "blacklanternsecurity.com",
        "email_domains": [
            "blacklanternsecurity.com",
            "blacklanternsecurity.onmicrosoft.com",
            "blsgvt.com",
            "o365.blacklanternsecurity.com",
        ],
    }

    async def setup_after_prep(self, module_test):
        # Use custom response for this test
        module_test.blasthttp_mock.add_response(
            url="https://azmap.dev/api/tenant?domain=blacklanternsecurity.com&extract=true",
            json=self.tenant_response,
        )

        module_test.blasthttp_mock.add_response(
            url="https://odc.officeapps.live.com/odc/v2.1/federationprovider?domain=blacklanternsecurity.com",
            json={"TenantId": "cc74fc12-4142-400e-a653-f98bdeadbeef"},
        )

        module_test.blasthttp_mock.add_response(
            url="https://login.microsoftonline.com/blacklanternsecurity.com/.well-known/openid-configuration",
            json={
                "tenant_region_scope": "NA",
                "cloud_instance_name": "microsoftonline.com",
            },
        )

        module_test.blasthttp_mock.add_response(
            url="https://login.microsoftonline.com/common/GetCredentialType",
            json={"EstsProperties": {}, "Credentials": {}},
        )

        module_test.blasthttp_mock.add_response(
            url="https://login.microsoftonline.com/common/userrealm/test@blacklanternsecurity.com?api-version=2.0",
            json={"NameSpaceType": "Managed"},
        )

        module_test.blasthttp_mock.add_response(
            url="https://mta-sts.blacklanternsecurity.com/.well-known/mta-sts.txt",
            status_code=404,
        )

        # Directory sync check
        module_test.blasthttp_mock.add_response(
            url="https://login.microsoftonline.com/common/GetCredentialType",
            json={"IfExistsResult": 1},
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


class TestAzure_Tenant_DesktopSSO(AzureTenantTestBase):
    """Test Desktop SSO detection and FINDING emission"""

    desktop_sso_enabled = True

    def check(self, module_test, events):
        assert any(e.type == "AZURE_TENANT" and e.data.get("desktop-sso-enabled") is True for e in events), (
            "AZURE_TENANT should have desktop-sso-enabled=True"
        )

        assert any(
            e.type == "FINDING"
            and e.data.get("name") == "Azure AD Desktop SSO Enabled"
            and e.data.get("severity") == "INFO"
            and e.data.get("confidence") == "MEDIUM"
            and "azure-sso" in e.tags
            for e in events
        ), "Should emit Desktop SSO FINDING with correct severity and confidence"


class TestAzure_Tenant_CertificateAuth(AzureTenantTestBase):
    """Test Certificate-Based Authentication detection"""

    certificate_auth_enabled = True

    def check(self, module_test, events):
        assert any(e.type == "AZURE_TENANT" and e.data.get("certificate-auth-enabled") is True for e in events), (
            "AZURE_TENANT should have certificate-auth-enabled=True"
        )

        assert any(
            e.type == "FINDING"
            and e.data.get("name") == "Certificate-Based Authentication Enabled"
            and e.data.get("severity") == "INFO"
            and e.data.get("confidence") == "HIGH"
            and "azure-cba" in e.tags
            for e in events
        ), "Should emit Certificate Auth FINDING with correct severity and confidence"


class TestAzure_Tenant_GovCloud(AzureTenantTestBase):
    """Test Government Cloud detection (DoD)"""

    cloud_type = "dod"

    def check(self, module_test, events):
        assert any(e.type == "AZURE_TENANT" and e.data.get("cloud-type") == "dod" for e in events), (
            "AZURE_TENANT should have cloud-type=dod"
        )

        assert any(
            e.type == "FINDING"
            and e.data.get("name") == "Azure Government Cloud Tenant"
            and e.data.get("severity") == "INFO"
            and e.data.get("confidence") == "HIGH"
            and "azure-gov-cloud" in e.tags
            for e in events
        ), "Should emit Government Cloud FINDING with HIGH severity"


class TestAzure_Tenant_GCCHigh(AzureTenantTestBase):
    """Test GCC High Government Cloud detection"""

    cloud_type = "gcc-high"

    def check(self, module_test, events):
        assert any(e.type == "AZURE_TENANT" and e.data.get("cloud-type") == "gcc-high" for e in events), (
            "AZURE_TENANT should have cloud-type=gcc-high"
        )

        assert any(
            e.type == "FINDING"
            and e.data.get("name") == "Azure Government Cloud Tenant"
            and "gcc-high" in e.data.get("description", "")
            and "azure-gov-cloud" in e.tags
            for e in events
        ), "Should emit Government Cloud FINDING for GCC High"


class TestAzure_Tenant_DirectorySync(AzureTenantTestBase):
    """Test Directory Synchronization detection"""

    include_onmicrosoft = True
    directory_sync_enabled = True

    def check(self, module_test, events):
        assert any(e.type == "AZURE_TENANT" and e.data.get("directory-sync-enabled") is True for e in events), (
            "AZURE_TENANT should have directory-sync-enabled=True"
        )

        assert any(
            e.type == "FINDING"
            and e.data.get("name") == "Directory Synchronization Enabled"
            and e.data.get("severity") == "INFO"
            and e.data.get("confidence") == "HIGH"
            and "azure-dir-sync" in e.tags
            for e in events
        ), "Should emit Directory Sync FINDING"


class TestAzure_Tenant_FederatedAuth(AzureTenantTestBase):
    """Test Federated Authentication detection"""

    federation_url = "https://authfs.example.com/adfs/ls/?username=test%40blacklanternsecurity.com"

    def check(self, module_test, events):
        assert any(
            e.type == "AZURE_TENANT" and e.data.get("federation-redirect-url") == self.federation_url for e in events
        ), "AZURE_TENANT should have federation-redirect-url"

        assert any(
            e.type == "FINDING"
            and e.data.get("name") == "Federated Authentication Detected"
            and e.data.get("severity") == "INFO"
            and e.data.get("confidence") == "HIGH"
            and e.data.get("full_url") == self.federation_url  # full_url preserves query string
            and e.data.get("url") == "https://authfs.example.com/adfs/ls/"  # url is cleaned
            and "azure-federated" in e.tags
            for e in events
        ), "Should emit Federated Auth FINDING with INFO severity"

        # URL_UNVERIFIED also gets cleaned (query string removed)
        assert any(
            e.type == "URL_UNVERIFIED" and e.url == "https://authfs.example.com/adfs/ls/" and "ms-auth-url" in e.tags
            for e in events
        ), "Should emit URL_UNVERIFIED for federation URL"


class TestAzure_Tenant_ExchangeOnline(AzureTenantTestBase):
    """Test Exchange Online detection via MTA-STS"""

    exchange_online = True

    def check(self, module_test, events):
        assert any(e.type == "AZURE_TENANT" and e.data.get("exchange-online") is True for e in events), (
            "AZURE_TENANT should have exchange-online=True"
        )

        assert any(e.type == "AZURE_TENANT" and e.data.get("mta-sts-mode") == "enforce" for e in events), (
            "AZURE_TENANT should have mta-sts-mode"
        )
