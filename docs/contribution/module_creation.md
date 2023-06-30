# Creating a Module

Writing a module is easy and requires only a basic understanding of Python. It consists of a few steps:

1. Create a new `.py` file in `bbot/modules`
1. At the top of the file, import `BaseModule`
1. Declare a class that inherits from `BaseModule`
    - the class must have the same name as your file (case-insensitive)
1. Define (via `watched_events` and `produced_events`) what types of events your module consumes
1. Define (via `flags`) whether your module is `active` or `passive`
1. Override `.handle_event()`
    - this is where you put your custom code

Here is a simple example of a working module (`bbot/modules/mymodule.py`):
~~~python
from bbot.modules.base import BaseModule

class MyModule(BaseModule):
    """
    Resolve DNS_NAMEs to IPs
    """
    watched_events = ["DNS_NAME"]
    produced_events = ["IP_ADDRESS"]
    flags = ["passive"]

    async def handle_event(self, event):
        for ip in await self.helpers.resolve(event.data):
            self.emit_event(ip, "IP_ADDRESS", source=event)
~~~

### Module Dependencies

BBOT automates module dependencies with **Ansible**. If your module relies on a third-party binary, OS package, or python library, you can specify them in the `deps_*` attributes of your module.

~~~python
class MyModule(BaseModule):
    ...
    deps_pip = ["beautifulsoup4"]
    deps_apt = ["chromium-browser"]
    deps_ansible = [
        {
            "name": "install dev tools",
            "package": {"name": ["gcc", "git", "make"], "state": "present"},
            "become": True,
            "ignore_errors": True,
        },
        {
            "name": "Download massdns source code",
            "git": {
                "repo": "https://github.com/blechschmidt/massdns.git",
                "dest": "#{BBOT_TEMP}/massdns",
                "single_branch": True,
                "version": "master",
            },
        },
        {
            "name": "Build massdns",
            "command": {"chdir": "#{BBOT_TEMP}/massdns", "cmd": "make", "creates": "#{BBOT_TEMP}/massdns/bin/massdns"},
        },
        {
            "name": "Install massdns",
            "copy": {"src": "#{BBOT_TEMP}/massdns/bin/massdns", "dest": "#{BBOT_TOOLS}/", "mode": "u+x,g+x,o+x"},
        },
    ]
~~~


