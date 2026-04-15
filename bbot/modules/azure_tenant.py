import asyncio

from bbot.modules.base import BaseModule


class azure_tenant(BaseModule):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME", "AZURE_TENANT", "FINDING", "URL_UNVERIFIED"]
    flags = ["safe", "affiliates", "subdomain-enum", "cloud-enum", "passive"]
    meta = {
        "description": "Query Azure for tenant information using multiple enumeration methods",
        "created_date": "2024-07-04",
        "author": "@TheTechromancer",
    }

    base_url = "https://azmap.dev/api/tenant"
    in_scope_only = True
    per_domain_only = True

    async def setup(self):
        self.processed = set()
        return True

    async def handle_event(self, event):
        _, query = self.helpers.split_domain(event.data)

        # 1. Query azmap.dev for tenant domains (keep for OPSEC)
        tenant_data = await self.query_azmap(query)

        if not tenant_data:
            return

        # 2. Gather additional data from multiple sources in parallel
        onmicrosoft_domain = self._get_onmicrosoft_domain(tenant_data)

        # Run all queries in parallel
        results = await asyncio.gather(
            self.query_odc(query),
            self.query_openid(query),
            self.query_getcredentialtype(query),
            self.query_userrealm_v2(query),
            self.query_mtasts(query),
        )
        odc_data, openid_data, getcred_data, userrealm_data, mtasts_data = results

        # 3. Check for directory sync if we have .onmicrosoft.com domain
        sync_data = await self.query_directory_sync(onmicrosoft_domain) if onmicrosoft_domain else {}

        # 4. Merge all data sources into comprehensive event
        azure_tenant_event = self.merge_tenant_data(
            query, tenant_data, odc_data, openid_data, getcred_data, userrealm_data, mtasts_data, sync_data
        )

        # 5. Emit DNS_NAME events for discovered domains (existing functionality)
        await self.emit_discovered_domains(event, tenant_data, query)

        # 6. Emit comprehensive AZURE_TENANT event
        tenant_names = azure_tenant_event.get("tenant-names", [])
        tenant_names_str = ",".join(tenant_names)
        await self.emit_event(
            azure_tenant_event,
            "AZURE_TENANT",
            parent=event,
            context=f'{{module}} performed comprehensive Azure tenant enumeration for "{query}" and found {{event.type}}: {tenant_names_str}',
        )

        # 7. Emit FINDING events for notable discoveries
        await self.emit_findings(event, query, azure_tenant_event)

    async def query_azmap(self, domain):
        """Query azmap.dev API for tenant domains (existing functionality)."""
        url = f"{self.base_url}?domain={domain}&extract=true"

        self.debug(f"Retrieving tenant domains at {url}")

        r = await self.helpers.request(url)
        status_code = getattr(r, "status_code", 0)
        if status_code != 200:
            self.verbose(f'Error retrieving azure_tenant domains for "{domain}" (status code: {status_code})')
            return {}

        try:
            tenant_data = r.json()
        except Exception as e:
            self.warning(f'Error parsing JSON response for "{domain}": {e}')
            return {}

        # Absorb domains into word cloud
        email_domains = tenant_data.get("email_domains", [])
        for d in email_domains:
            d = str(d).lower()
            _, query = self.helpers.split_domain(d)
            self.processed.add(hash(query))
            self.scan.word_cloud.absorb_word(d)

        return tenant_data

    async def query_odc(self, domain):
        """Query odc.officeapps.live.com for tenant ID and org name."""
        url = f"https://odc.officeapps.live.com/odc/v2.1/federationprovider?domain={domain}"

        try:
            r = await self.helpers.request(url)
            if r is None:
                self.debug(f"No response from ODC endpoint for {domain}")
                return {}

            status_code = getattr(r, "status_code", 0)
            if status_code != 200:
                self.debug(f"ODC endpoint returned status {status_code} for {domain}")
                return {}

            data = r.json()
            if not data or not isinstance(data, dict):
                return {}

            # Extract relevant fields
            result = {}
            if "TenantId" in data:
                result["tenant-id"] = data["TenantId"]
            if "FederationBrandName" in data:
                result["federation-brand-name"] = data["FederationBrandName"]

            return result

        except Exception as e:
            self.debug(f"Error querying ODC endpoint for {domain}: {e}")
            return {}

    async def query_openid(self, domain):
        """Query OpenID configuration for region and cloud type."""
        url = f"https://login.microsoftonline.com/{domain}/.well-known/openid-configuration"

        try:
            r = await self.helpers.request(url)
            if r is None:
                self.debug(f"No response from OpenID endpoint for {domain}")
                return {}

            status_code = getattr(r, "status_code", 0)
            if status_code == 404:
                self.debug(f"Domain {domain} not registered to Azure AD (OpenID config returned 404)")
                return {}
            if status_code != 200:
                self.debug(f"OpenID endpoint returned status {status_code} for {domain}")
                return {}

            data = r.json()
            if not data or not isinstance(data, dict):
                return {}

            # Extract relevant fields
            result = {}
            if "tenant_region_scope" in data:
                result["tenant-region"] = data["tenant_region_scope"]
            if "tenant_region_sub_scope" in data:
                result["tenant-region-sub"] = data["tenant_region_sub_scope"]
            if "cloud_instance_name" in data:
                result["cloud-instance"] = data["cloud_instance_name"]

            return result

        except Exception as e:
            self.debug(f"Error querying OpenID endpoint for {domain}: {e}")
            return {}

    async def query_getcredentialtype(self, domain):
        """Query GetCredentialType API for Desktop SSO, CBA, and federation info."""
        url = "https://login.microsoftonline.com/common/GetCredentialType"
        headers = {"Content-Type": "application/json; charset=UTF-8"}

        body = {
            "username": f"test@{domain}",
            "isOtherIdpSupported": True,
            "checkPhones": True,
            "isRemoteNGCSupported": True,
            "isCookieBannerShown": False,
            "isFidoSupported": True,
            "isAccessPassSupported": True,
        }

        try:
            r = await self.helpers.request(url, method="POST", headers=headers, json=body)
            if r is None:
                self.debug(f"No response from GetCredentialType endpoint for {domain}")
                return {}

            status_code = getattr(r, "status_code", 0)
            if status_code != 200:
                self.debug(f"GetCredentialType endpoint returned status {status_code} for {domain}")
                return {}

            data = r.json()
            if not data or not isinstance(data, dict):
                return {}

            # Extract relevant fields
            result = {}

            # Desktop SSO and CBA from EstsProperties
            ests_props = data.get("EstsProperties", {})
            if isinstance(ests_props, dict):
                if "DesktopSsoEnabled" in ests_props:
                    result["desktop-sso-enabled"] = ests_props["DesktopSsoEnabled"]
                if "DomainType" in ests_props:
                    result["domain-type"] = ests_props["DomainType"]

            # Certificate auth from Credentials
            credentials = data.get("Credentials", {})
            if isinstance(credentials, dict):
                if "HasCertAuth" in credentials:
                    result["certificate-auth-enabled"] = credentials["HasCertAuth"]
                if "FederationRedirectUrl" in credentials:
                    result["federation-redirect-url"] = credentials["FederationRedirectUrl"]

            return result

        except Exception as e:
            self.debug(f"Error querying GetCredentialType endpoint for {domain}: {e}")
            return {}

    async def query_userrealm_v2(self, domain):
        """Query UserRealm v2.0 API for account type and branding."""
        url = f"https://login.microsoftonline.com/common/userrealm/test@{domain}?api-version=2.0"

        try:
            r = await self.helpers.request(url)
            if r is None:
                self.debug(f"No response from UserRealm v2.0 endpoint for {domain}")
                return {}

            status_code = getattr(r, "status_code", 0)
            if status_code != 200:
                self.debug(f"UserRealm v2.0 endpoint returned status {status_code} for {domain}")
                return {}

            data = r.json()
            if not data or not isinstance(data, dict):
                return {}

            # Extract relevant fields
            result = {}
            if "NameSpaceType" in data:
                result["account-type"] = data["NameSpaceType"]

            # Extract branding information if available
            branding_info = data.get("TenantBrandingInfo")
            if branding_info and isinstance(branding_info, list) and len(branding_info) > 0:
                branding = branding_info[0]
                if isinstance(branding, dict):
                    branding_data = {}
                    if "BannerLogo" in branding:
                        branding_data["banner-logo"] = branding["BannerLogo"]
                    if "TileLogo" in branding:
                        branding_data["tile-logo"] = branding["TileLogo"]
                    if "BackgroundColor" in branding:
                        branding_data["background-color"] = branding["BackgroundColor"]
                    if branding_data:
                        result["tenant-branding"] = branding_data

            return result

        except Exception as e:
            self.debug(f"Error querying UserRealm v2.0 endpoint for {domain}: {e}")
            return {}

    async def query_mtasts(self, domain):
        """Query MTA-STS policy to detect Exchange Online."""
        url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"

        try:
            r = await self.helpers.request(url)
            if r is None:
                self.debug(f"No response from MTA-STS endpoint for {domain}")
                return {}

            status_code = getattr(r, "status_code", 0)
            if status_code == 404:
                self.debug(f"No MTA-STS policy found for {domain}")
                return {}
            if status_code != 200:
                self.debug(f"MTA-STS endpoint returned status {status_code} for {domain}")
                return {}

            content = r.text
            if not content:
                return {}

            # Check if Exchange Online is in the MX records
            result = {}
            if "mail.protection.outlook.com" in content.lower():
                result["exchange-online"] = True
                result["mta-sts-mode"] = None

                # Extract mode if present
                for line in content.split("\n"):
                    if line.startswith("mode:"):
                        result["mta-sts-mode"] = line.split(":", 1)[1].strip()
                        break

            return result

        except Exception as e:
            self.debug(f"Error querying MTA-STS endpoint for {domain}: {e}")
            return {}

    async def query_directory_sync(self, onmicrosoft_domain):
        """Check if directory sync is enabled by testing for sync service account."""
        if not onmicrosoft_domain:
            return {}

        url = "https://login.microsoftonline.com/common/GetCredentialType"
        headers = {"Content-Type": "application/json; charset=UTF-8"}

        sync_username = f"ADToAADSyncServiceAccount@{onmicrosoft_domain}"
        body = {
            "username": sync_username,
            "isOtherIdpSupported": True,
            "checkPhones": False,
            "isRemoteNGCSupported": False,
            "isCookieBannerShown": False,
            "isFidoSupported": False,
            "isAccessPassSupported": False,
        }

        try:
            r = await self.helpers.request(url, method="POST", headers=headers, json=body)
            if r is None:
                self.debug(f"No response from GetCredentialType for directory sync check on {onmicrosoft_domain}")
                return {}

            status_code = getattr(r, "status_code", 0)
            if status_code != 200:
                self.debug(f"GetCredentialType returned status {status_code} for directory sync check")
                return {}

            data = r.json()
            if not data or not isinstance(data, dict):
                return {}

            # If IfExistsResult is 0, the sync account exists
            if_exists_result = data.get("IfExistsResult")
            if if_exists_result == 0:
                return {"directory-sync-enabled": True}

            return {}

        except Exception as e:
            self.debug(f"Error checking directory sync for {onmicrosoft_domain}: {e}")
            return {}

    def merge_tenant_data(
        self, query, tenant_data, odc_data, openid_data, getcred_data, userrealm_data, mtasts_data, sync_data
    ):
        """Merge data from all sources into single comprehensive event."""

        # Start with azmap.dev data (backward compatibility)
        tenant_names = []
        tenant_name = tenant_data.get("tenant_name")
        if tenant_name:
            tenant_names.append(tenant_name)

        # Extract tenant names from .onmicrosoft.com domains
        email_domains = tenant_data.get("email_domains", [])
        for domain in email_domains:
            if domain.lower().endswith(".onmicrosoft.com"):
                tenantname = domain.split(".")[0].lower()
                if tenantname and tenantname not in tenant_names:
                    tenant_names.append(tenantname)

        merged = {"tenant-names": tenant_names, "domains": sorted(email_domains)}

        # Tenant ID: prefer ODC, fallback to azmap.dev
        tenant_id = odc_data.get("tenant-id") or tenant_data.get("tenant_id")
        if tenant_id:
            merged["tenant-id"] = tenant_id

        # Federation brand name from ODC
        if odc_data.get("federation-brand-name"):
            merged["federation-brand-name"] = odc_data["federation-brand-name"]

        # OpenID configuration data
        if openid_data.get("tenant-region"):
            merged["tenant-region"] = openid_data["tenant-region"]
        if openid_data.get("tenant-region-sub") is not None:
            merged["tenant-region-sub"] = openid_data["tenant-region-sub"]
        if openid_data.get("cloud-instance"):
            merged["cloud-instance"] = openid_data["cloud-instance"]
        if openid_data:
            merged["cloud-type"] = self._derive_cloud_type(openid_data)

        # GetCredentialType data
        if getcred_data:
            if getcred_data.get("desktop-sso-enabled") is not None:
                merged["desktop-sso-enabled"] = getcred_data["desktop-sso-enabled"]
            if getcred_data.get("certificate-auth-enabled") is not None:
                merged["certificate-auth-enabled"] = getcred_data["certificate-auth-enabled"]
            if getcred_data.get("domain-type") is not None:
                merged["domain-type"] = getcred_data["domain-type"]
            if getcred_data.get("federation-redirect-url"):
                merged["federation-redirect-url"] = getcred_data["federation-redirect-url"]

        # UserRealm v2.0 data
        if userrealm_data:
            if userrealm_data.get("account-type"):
                merged["account-type"] = userrealm_data["account-type"]
            if userrealm_data.get("tenant-branding"):
                merged["tenant-branding"] = userrealm_data["tenant-branding"]

        # MTA-STS data
        if mtasts_data.get("exchange-online") is not None:
            merged["exchange-online"] = mtasts_data["exchange-online"]
        if mtasts_data.get("mta-sts-mode"):
            merged["mta-sts-mode"] = mtasts_data["mta-sts-mode"]

        # Directory sync data
        if sync_data and sync_data.get("directory-sync-enabled"):
            merged["directory-sync-enabled"] = True

        return merged

    async def emit_discovered_domains(self, event, tenant_data, query):
        """Emit DNS_NAME events for discovered domains (existing functionality)."""
        email_domains = tenant_data.get("email_domains", [])
        if email_domains:
            self.verbose(
                f'Found {len(email_domains):,} domains under tenant for "{query}": {", ".join(sorted(email_domains))}'
            )
            for domain in email_domains:
                if domain != query:
                    await self.emit_event(
                        domain,
                        "DNS_NAME",
                        parent=event,
                        tags=["affiliate", "azure-tenant"],
                        context=f'{{module}} queried azmap.dev for "{query}" and found {{event.type}}: {{event.pretty_string}}',
                    )

    async def emit_findings(self, event, domain, tenant_data):
        """Emit FINDING events for notable security-relevant discoveries."""

        # Desktop SSO
        if tenant_data.get("desktop-sso-enabled"):
            await self.emit_event(
                {
                    "host": domain,
                    "name": "Azure AD Desktop SSO Enabled",
                    "description": f"Azure AD Desktop SSO (Seamless SSO) is enabled for {domain}, indicating pass-through authentication or password hash sync from on-premises Active Directory. This reveals hybrid infrastructure where compromising the on-premises environment could provide a pivot point into Azure AD.",
                    "severity": "INFO",
                    "confidence": "MEDIUM",
                },
                "FINDING",
                parent=event,
                tags=["azure-sso"],
            )

        # Certificate-based Auth
        if tenant_data.get("certificate-auth-enabled"):
            await self.emit_event(
                {
                    "host": domain,
                    "name": "Certificate-Based Authentication Enabled",
                    "description": f"Certificate-based authentication is enabled for {domain}. This provides an alternative authentication vector where stolen or compromised certificates can be used for access, potentially bypassing MFA and password-based security controls.",
                    "severity": "INFO",
                    "confidence": "HIGH",
                },
                "FINDING",
                parent=event,
                tags=["azure-cba"],
            )

        # Government Cloud
        cloud_type = tenant_data.get("cloud-type")
        if cloud_type in ["gcc-high", "dod"]:
            await self.emit_event(
                {
                    "host": domain,
                    "name": "Azure Government Cloud Tenant",
                    "description": f"{domain} is hosted on Azure Government Cloud ({cloud_type}), indicating a high-value target that likely handles sensitive government data, classified information, or critical infrastructure systems.",
                    "severity": "INFO",
                    "confidence": "HIGH",
                },
                "FINDING",
                parent=event,
                tags=["azure-gov-cloud"],
            )

        # Directory Sync
        if tenant_data.get("directory-sync-enabled"):
            await self.emit_event(
                {
                    "host": domain,
                    "name": "Directory Synchronization Enabled",
                    "description": f"Directory synchronization (Azure AD Connect or Cloud Sync) is enabled for {domain}, indicating hybrid identity infrastructure. Compromising the on-premises Active Directory would allow an attacker to sync malicious changes to Azure AD, including creating backdoor accounts.",
                    "severity": "INFO",
                    "confidence": "HIGH",
                },
                "FINDING",
                parent=event,
                tags=["azure-dir-sync"],
            )

        # Federated Domain
        fed_url = tenant_data.get("federation-redirect-url")
        if fed_url:
            await self.emit_event(
                {
                    "host": domain,
                    "url": fed_url,
                    "full_url": fed_url,  # Preserve full URL with query string
                    "name": "Federated Authentication Detected",
                    "description": f"{domain} uses federated authentication with an external identity provider at {fed_url}. Compromising the federated IdP would grant access to Azure AD, and misconfigurations in the federation trust can be exploited (e.g., Golden SAML attacks).",
                    "severity": "INFO",
                    "confidence": "HIGH",
                },
                "FINDING",
                parent=event,
                tags=["azure-federated"],
            )
            # Also emit URL for further enumeration (ms-auth-url tag triggers oauth module OIDC check)
            fed_url_event = self.make_event(
                fed_url,
                "URL_UNVERIFIED",
                parent=event,
                tags=["affiliate", "ms-auth-url"],
            )
            if fed_url_event:
                await self.emit_event(fed_url_event)

    def _derive_cloud_type(self, openid_data):
        """Derive cloud type from OpenID configuration data."""
        sub_scope = openid_data.get("tenant-region-sub")

        if sub_scope is None:
            return "commercial"
        elif sub_scope == "DOD":
            return "dod"
        elif sub_scope == "DODCON":
            return "gcc-high"
        else:
            return "government"

    def _get_onmicrosoft_domain(self, tenant_data):
        """Extract the .onmicrosoft.com domain from tenant data."""
        email_domains = tenant_data.get("email_domains", [])
        for domain in email_domains:
            if domain.lower().endswith(".onmicrosoft.com"):
                return domain
        return None
