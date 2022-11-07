from .base import BaseCloudProvider


class Azure(BaseCloudProvider):
    domains = [
        "windows.net",
        "azure.com",
        "azmk8s.io",
        "azure-api.net",
        "azure-mobile.net",
        "azurecontainer.io",
        "azurecr.io",
        "azureedge.net",
        "azurefd.net",
        "azurewebsites.net",
        "cloudapp.net",
        "onmicrosoft.com",
        "trafficmanager.net",
        "vault.azure.net",
        "visualstudio.com",
        "vo.msecnd.net",
    ]

    bucket_name_regex = r"[a-z0-9][a-z0-9-_\.]{1,61}[a-z0-9]"
    regexes = {"STORAGE_BUCKET": [r"(%[a-f0-9]{2})?(" + bucket_name_regex + r")\.(blob\.core\.windows\.net)"]}
