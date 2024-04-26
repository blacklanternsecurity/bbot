# based on https://github.com/ElSicarius/interactsh-python/blob/main/sources/interactsh.py
import json
import base64
import random
import asyncio
import logging
import traceback
from uuid import uuid4

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

from bbot.errors import InteractshError

log = logging.getLogger("bbot.core.helpers.interactsh")

server_list = ["oast.pro", "oast.live", "oast.site", "oast.online", "oast.fun", "oast.me"]


class Interactsh:
    """
    A pure python implementation of ProjectDiscovery's interact.sh.

    *"Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions."*

    - https://app.interactsh.com
    - https://github.com/projectdiscovery/interactsh

    This class facilitates interactions with the interact.sh service for
    out-of-band data exfiltration and vulnerability confirmation. It allows
    for customization by accepting server and token parameters from the
    configuration provided by `parent_helper`.

    Attributes:
        parent_helper (ConfigAwareHelper): An instance of a helper class containing configuration data.
        server (str): The server to be used. If None (the default), a random server will be chosen from a predetermined list.
        correlation_id (str): An identifier to correlate requests and responses. Default is None.
        custom_server (str): Optional. A custom interact.sh server. Loaded from configuration.
        token (str): Optional. A token for interact.sh API. Loaded from configuration.
        _poll_task (AsyncTask): The task responsible for polling the interact.sh server.

    Examples:
        ```python
        # instantiate interact.sh client (no requests are sent yet)
        >>> interactsh_client = self.helpers.interactsh()
        # register with an interact.sh server
        >>> interactsh_domain = await interactsh_client.register()
        [INFO] Registering with interact.sh server: oast.me
        [INFO] Successfully registered to interactsh server oast.me with correlation_id rg99x2f860h5466ou3so [rg99x2f860h5466ou3so86i07n1m3013k.oast.me]
        # simulate an out-of-band interaction
        >>> await self.helpers.request(f"https://{interactsh_domain}/test")
        # wait for out-of-band interaction to be registered
        >>> await asyncio.sleep(10)
        >>> data_list = await interactsh_client.poll()
        >>> print(data_list)
        [
            {
                "protocol": "dns",
                "unique-id": "rg99x2f860h5466ou3so86i07n1m3013k",
                "full-id": "rg99x2f860h5466ou3so86i07n1m3013k",
                "q-type": "A",
                "raw-request": "...",
                "remote-address": "1.2.3.4",
                "timestamp": "2023-09-15T21:09:23.187226851Z"
            },
            {
                "protocol": "http",
                "unique-id": "rg99x2f860h5466ou3so86i07n1m3013k",
                "full-id": "rg99x2f860h5466ou3so86i07n1m3013k",
                "raw-request": "GET /test HTTP/1.1 ...",
                "remote-address": "1.2.3.4",
                "timestamp": "2023-09-15T21:09:24.155677967Z"
            }
        ]
        # finally, shut down the client
        >>> await interactsh_client.deregister()
        ```
    """

    def __init__(self, parent_helper, poll_interval=10):
        self.parent_helper = parent_helper
        self.server = None
        self.correlation_id = None
        self.custom_server = self.parent_helper.config.get("interactsh_server", None)
        self.token = self.parent_helper.config.get("interactsh_token", None)
        self.poll_interval = poll_interval
        self._poll_task = None

    async def register(self, callback=None):
        """
        Registers the instance with an interact.sh server and sets up polling.

        Generates RSA keys for secure communication, builds a correlation ID,
        and sends a POST request to an interact.sh server to register. Optionally,
        starts an asynchronous polling task to listen for interactions.

        Args:
            callback (callable, optional): A function to be called each time new interactions are received.

        Returns:
            str: The registered domain for out-of-band interactions.

        Raises:
            InteractshError: If registration with an interact.sh server fails.

        Examples:
            >>> interactsh_client = self.helpers.interactsh()
            >>> registered_domain = await interactsh_client.register()
            [INFO] Registering with interact.sh server: oast.me
            [INFO] Successfully registered to interactsh server oast.me with correlation_id rg99x2f860h5466ou3so [rg99x2f860h5466ou3so86i07n1m3013k.oast.me]
        """
        rsa = RSA.generate(1024)

        self.public_key = rsa.publickey().exportKey()
        self.private_key = rsa.exportKey()

        encoded_public_key = base64.b64encode(self.public_key).decode("utf8")

        uuid = uuid4().hex.ljust(33, "a")
        guid = "".join(i if i.isdigit() else chr(ord(i) + random.randint(0, 20)) for i in uuid)

        self.correlation_id = guid[:20]
        self.secret = str(uuid4())
        headers = {}

        if self.custom_server:
            if not self.token:
                log.verbose("Interact.sh token is not set")
            else:
                headers["Authorization"] = self.token
            self.server_list = [str(self.custom_server)]
        else:
            self.server_list = random.sample(server_list, k=len(server_list))
        for server in self.server_list:
            log.info(f"Registering with interact.sh server: {server}")
            data = {
                "public-key": encoded_public_key,
                "secret-key": self.secret,
                "correlation-id": self.correlation_id,
            }
            r = await self.parent_helper.request(
                f"https://{server}/register", headers=headers, json=data, method="POST"
            )
            if r is None:
                continue
            try:
                msg = r.json().get("message", "")
                assert "registration successful" in msg
            except Exception:
                log.debug(f"Failed to register with interactsh server {self.server}")
                continue
            self.server = server
            self.domain = f"{guid}.{self.server}"
            break

        if not self.server:
            raise InteractshError(f"Failed to register with an interactsh server")

        log.info(
            f"Successfully registered to interactsh server {self.server} with correlation_id {self.correlation_id} [{self.domain}]"
        )

        if callable(callback):
            self._poll_task = asyncio.create_task(self.poll_loop(callback))

        return self.domain

    async def deregister(self):
        """
        Deregisters the instance from the interact.sh server and cancels the polling task.

        Sends a POST request to the server to deregister, using the correlation ID
        and secret key generated during registration. Optionally, if a polling
        task was started, it is cancelled.

        Raises:
            InteractshError: If required information is missing or if deregistration fails.

        Examples:
            >>> await interactsh_client.deregister()
        """
        if not self.server or not self.correlation_id or not self.secret:
            raise InteractshError(f"Missing required information to deregister")

        headers = {}
        if self.token:
            headers["Authorization"] = self.token

        data = {"secret-key": self.secret, "correlation-id": self.correlation_id}

        r = await self.parent_helper.request(
            f"https://{self.server}/deregister", headers=headers, json=data, method="POST"
        )

        if self._poll_task is not None:
            self._poll_task.cancel()

        if "success" not in getattr(r, "text", ""):
            raise InteractshError(f"Failed to de-register with interactsh server {self.server}")

    async def poll(self):
        """
        Polls the interact.sh server for interactions tied to the current instance.

        Sends a GET request to the server to fetch interactions associated with the
        current correlation_id and secret key. Returned interactions are decrypted
        using an AES key provided by the server response.

        Raises:
            InteractshError: If required information for polling is missing.

        Returns:
            list: A list of decrypted interaction data dictionaries.

        Examples:
            >>> data_list = await interactsh_client.poll()
            >>> print(data_list)
            [
                {
                    "protocol": "dns",
                    "unique-id": "rg99x2f860h5466ou3so86i07n1m3013k",
                    ...
                },
                ...
            ]
        """
        if not self.server or not self.correlation_id or not self.secret:
            raise InteractshError(f"Missing required information to poll")

        headers = {}
        if self.token:
            headers["Authorization"] = self.token

        try:
            r = await self.parent_helper.request(
                f"https://{self.server}/poll?id={self.correlation_id}&secret={self.secret}", headers=headers
            )
            if r is None:
                raise InteractshError("Error polling interact.sh: No response from server")

            ret = []
            data_list = r.json().get("data", None)
            if data_list:
                aes_key = r.json()["aes_key"]

                for data in data_list:
                    decrypted_data = self._decrypt(aes_key, data)
                    ret.append(decrypted_data)
            return ret
        except Exception as e:
            raise InteractshError(f"Error polling interact.sh: {e}")

    async def poll_loop(self, callback):
        """
        Starts a polling loop to continuously check for interactions with the interact.sh server.

        Continuously polls the interact.sh server for interactions tied to the current instance,
        using the `poll` method. When interactions are received, it executes the given callback
        function with each interaction data.

        Parameters:
            callback (callable): The function to be called for every interaction received from the server.

        Returns:
            awaitable: An awaitable object that executes the internal `_poll_loop` method.

        Examples:
            >>> await interactsh_client.poll_loop(my_callback)
        """
        async with self.parent_helper.scan._acatch(context=self._poll_loop):
            return await self._poll_loop(callback)

    async def _poll_loop(self, callback):
        while 1:
            if self.parent_helper.scan.stopping:
                await asyncio.sleep(1)
                continue
            data_list = []
            try:
                data_list = await self.poll()
            except InteractshError as e:
                log.warning(e)
                log.trace(traceback.format_exc())
            if not data_list:
                await asyncio.sleep(self.poll_interval)
                continue
            for data in data_list:
                if data:
                    await self.parent_helper.execute_sync_or_async(callback, data)

    def _decrypt(self, aes_key, data):
        """
        Decrypts and returns the data received from the interact.sh server.

        Uses RSA and AES for decrypting the data. RSA with PKCS1_OAEP and SHA256 is used to decrypt the AES key,
        and then AES (CFB mode) is used to decrypt the actual data payload.

        Parameters:
            aes_key (str): The AES key for decryption, encrypted with RSA and base64 encoded.
            data (str): The data payload to decrypt, which is base64 encoded and AES encrypted.

        Returns:
            dict: The decrypted data, loaded as a JSON object.

        Examples:
            >>> decrypted_data = self._decrypt(aes_key, data)
        """
        private_key = RSA.importKey(self.private_key)
        cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        aes_plain_key = cipher.decrypt(base64.b64decode(aes_key))
        decode = base64.b64decode(data)
        bs = AES.block_size
        iv = decode[:bs]
        cryptor = AES.new(key=aes_plain_key, mode=AES.MODE_CFB, IV=iv, segment_size=128)
        plain_text = cryptor.decrypt(decode)
        return json.loads(plain_text[16:])
