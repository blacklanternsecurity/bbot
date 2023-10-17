# Command Helpers

These are helpers related to executing shell commands. They are used throughout BBOT and its modules for executing various binaries such as `nmap`, `nuclei`, etc.

Note that these helpers can be invoked directly from `self.helpers`, e.g.:

```python
self.helpers.run("ls", "-l")
```

::: bbot.core.helpers.command
    options:
      show_root_heading: false
