from bbot.modules.base import BaseModule


class postman(BaseModule):
    """
    A template module for use of the GitHub API
    Inherited by several other github modules.
    """

    base_url = "https://www.postman.com/_api"
    api_url = "https://api.getpostman.com"
    html_url = "https://www.postman.com"
    ping_url = f"{api_url}/me"

    headers = {
        "Content-Type": "application/json",
        "X-App-Version": "10.18.8-230926-0808",
        "X-Entity-Team-Id": "0",
        "Origin": "https://www.postman.com",
        "Referer": "https://www.postman.com/search?q=&scope=public&type=all",
    }
