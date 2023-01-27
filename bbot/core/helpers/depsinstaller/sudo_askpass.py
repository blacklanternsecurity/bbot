#!/usr/bin/env python3

import os

print(os.environ.get("BBOT_SUDO_PASS", ""), end="")
