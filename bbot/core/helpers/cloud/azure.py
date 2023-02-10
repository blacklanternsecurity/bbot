from .base import BaseCloudProvider


class Azure(BaseCloudProvider):
    domains = [
        "azmk8s.io",
        "azure-api.net",
        "azure-mobile.net",
        "azure.com",
        "azure.net",
        "azurecontainer.io",
        "azurecr.io",
        "azuredatalakestore.net",
        "azureedge.net",
        "azurefd.net",
        "azurehdinsight.net",
        "azurewebsites.net",
        "cloudapp.net",
        "windows.net",
        "onmicrosoft.com",
        "trafficmanager.net",
        "visualstudio.com",
        "vo.msecnd.net",
    ]

    bucket_name_regex = r"[a-z0-9][a-z0-9-_\.]{1,61}[a-z0-9]"
    regexes = {"STORAGE_BUCKET": [r"(%[a-f0-9]{2})?(" + bucket_name_regex + r")\.(blob\.core\.windows\.net)"]}
