# Command Helpers

These are helpers related to executing shell commands. They are used throughout BBOT and its modules for executing various binaries such as `nmap`, `nuclei`, etc.

These helpers can be invoked directly from `self.helpers`, but inside a module they should always use `self.run_process()` or `self.run_process_live()`. These are light wrappers which ensure the running process is tracked by the module so that it can be easily terminated should the user need to kill the module:

```python
# simple subprocess
ls_result = await self.run_process("ls", "-l")
for line ls_result.stdout.splitlines():
    # ...

# iterate through each line in real time
async for line in self.run_process_live(["grep", "-R"]):
    # ...
```

::: bbot.core.helpers.command
    options:
      show_root_heading: false
