#!/usr/bin/env python3
import os
import sys
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

ENV_VAR_NAME = "BBOT_SUDO_PASS"
KEY_ENV_VAR_PATH = "BBOT_SUDO_KEYFILE"


def decrypt_password(encrypted_data, key):
    iv, ciphertext = encrypted_data.split(":")
    iv = bytes.fromhex(iv)
    ct = bytes.fromhex(ciphertext)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode("utf-8")


def main():
    encrypted_password = os.environ.get(ENV_VAR_NAME, "")
    # remove variable from environment once we've got it
    os.environ.pop(ENV_VAR_NAME, None)
    encryption_keypath = Path(os.environ.get(KEY_ENV_VAR_PATH, ""))

    if not encrypted_password or not encryption_keypath.is_file():
        print("Error: Encrypted password or encryption key not found in environment variables.", file=sys.stderr)
        sys.exit(1)

    try:
        key = encryption_keypath.read_bytes()
        decrypted_password = decrypt_password(encrypted_password, key)
        print(decrypted_password, end="")
    except Exception as e:
        print(f'Error decrypting password "{encrypted_password}": {str(e)}', file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
