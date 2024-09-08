from bbot.modules.base import BaseModule


class postman(BaseModule):
    """
    A template module for use of the GitHub API
    Inherited by several other github modules.
    """

    base_url = "https://www.postman.com/_api"
    html_url = "https://www.postman.com"
