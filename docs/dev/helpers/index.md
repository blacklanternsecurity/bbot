# BBOT Helpers

In this section are various helper functions that are designed to make your life easier when devving on BBOT. Whether you're extending BBOT by writing a module or working on its core engine, these functions are designed to act as useful machine parts to perform essential tasks, such as making a web request or executing a DNS query.

The vast majority of these helpers can be accessed directly from the `.helpers` attribute of a scan or module, like so:

```python
class MyModule(BaseModule):

    ...

    async def handle_event(self, event):
        # Web Request
        response = await self.helpers.request("https://www.evilcorp.com")

        # DNS query
        for ip in await self.helpers.resolve("www.evilcorp.com"):
            self.hugesuccess(str(ip))

        # Execute shell command
        completed_process = await self.run_process("ls", "-l")
        self.hugesuccess(completed_process.stdout)

        # Split a DNS name into subdomain / domain
        self.helpers.split_domain("www.internal.evilcorp.co.uk")
        # ("www.internal", "evilcorp.co.uk")
```

[Next Up: Command Helpers -->](command.md){ .md-button .md-button--primary }
