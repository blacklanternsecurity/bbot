# based on https://github.com/ElSicarius/interactsh-python/blob/main/sources/interactsh.py
import json
import base64
import random
import logging
from time import sleep
from uuid import uuid4
from threading import Thread
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

from bbot.core.errors import InteractshError

log = logging.getLogger("bbot.core.helpers.interactsh")

server_list = ["oast.pro", "oast.live", "oast.site", "oast.online", "oast.fun", "oast.me"]


class Interactsh:
    def __init__(self, parent_helper):
        self.parent_helper = parent_helper
        self.server = self.parent_helper.config.get("interactsh_server", None)
        self.token = self.parent_helper.config.get("interactsh_token", None)
        self._thread = None

    def register(self, callback=None):
        if self.server == None:
            self.server = random.choice(server_list)

        rsa = RSA.generate(1024)

        self.public_key = rsa.publickey().exportKey()
        self.private_key = rsa.exportKey()

        encoded_public_key = base64.b64encode(self.public_key).decode("utf8")

        uuid = uuid4().hex.ljust(33, "a")
        guid = "".join(i if i.isdigit() else chr(ord(i) + random.randint(0, 20)) for i in uuid)

        self.domain = f"{guid}.{self.server}"

        self.correlation_id = guid[:20]
        self.secret = str(uuid4())
        headers = {}

        if self.token:
            headers["Authorization"] = self.token

        data = {"public-key": encoded_public_key, "secret-key": self.secret, "correlation-id": self.correlation_id}
        r = self.parent_helper.request(
            f"https://{self.server}/register", headers=headers, json=data, method="POST", retries="infinite"
        )
        msg = r.json().get("message", "")
        if msg != "registration successful":
            raise InteractshError(f"Failed to register with interactsh server {self.server}")

        log.info(
            f"Successfully registered to interactsh server {self.server} with correlation_id {self.correlation_id} [{self.domain}]"
        )

        if callable(callback):
            self._thread = Thread(target=self.poll_loop, args=(callback,), daemon=True)
            self._thread.start()

        return self.domain

    def deregister(self):

        headers = {}
        if self.token:
            headers["Authorization"] = self.token

        data = {"secret-key": self.secret, "correlation-id": self.correlation_id}

        r = self.parent_helper.request(f"https://{self.server}/deregister", headers=headers, json=data, method="POST")
        if "success" not in r.text:
            raise InteractshError(f"Failed to de-register with interactsh server {self.server}")

    def poll(self):

        headers = {}
        if self.token:
            headers["Authorization"] = self.token

        r = self.parent_helper.request(
            f"https://{self.server}/poll?id={self.correlation_id}&secret={self.secret}", headers=headers
        )

        data_list = r.json().get("data", None)
        if data_list:
            aes_key = r.json()["aes_key"]

            for data in data_list:

                decrypted_data = self.decrypt(aes_key, data)
                yield decrypted_data

    def poll_loop(self, callback):
        return self.parent_helper.scan.manager.catch(self._poll_loop, callback, _force=True)

    def _poll_loop(self, callback):
        while 1:
            if self.parent_helper.scan.stopping:
                sleep(1)
                continue
            data_list = list(self.poll())
            if not data_list:
                sleep(10)
                continue
            for data in data_list:
                if data:
                    callback(data)

    def decrypt(self, aes_key, data):
        private_key = RSA.importKey(self.private_key)
        cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        aes_plain_key = cipher.decrypt(base64.b64decode(aes_key))
        decode = base64.b64decode(data)
        bs = AES.block_size
        iv = decode[:bs]
        cryptor = AES.new(key=aes_plain_key, mode=AES.MODE_CFB, IV=iv, segment_size=128)
        plain_text = cryptor.decrypt(decode)
        return json.loads(plain_text[16:])
