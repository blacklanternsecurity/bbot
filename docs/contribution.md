# Contribution

We welcome contributions! If you have an idea for a new module, or are a Python developer who wants to get involved, please fork us or come talk to us on [Discord](https://discord.com/invite/PZqkgxu5SA).

## Setting Up a Dev Environment

### Installation (Poetry)

[Poetry](https://python-poetry.org/) is the recommended method of installation if you want to dev on BBOT. To set up a dev environment with Poetry, you can follow these steps:

- Fork [BBOT](https://github.com/blacklanternsecurity/bbot) on GitHub
- Clone your fork and set up a development environment with Poetry:

```bash
# clone your forked repo and cd into it
git clone git@github.com/<username>/bbot.git
cd bbot

# install poetry
curl -sSL https://install.python-poetry.org | python3 -

# install pip dependencies
poetry install
# install pre-commit hooks, etc.
poetry run pre-commit install

# enter virtual environment
poetry shell

bbot --help
```

- Now, any changes you make in the code will be reflected in the `bbot` command.
- After making your changes, run the tests locally to ensure they pass.

```bash
# auto-format code indentation, etc.
black .

# run tests
./bbot/test/run_tests.sh
```

- Finally, commit and push your changes, and create a pull request to the `dev` branch of the main BBOT repo.

#### Module Testing Requirements

Please note that the following requirements currently exist for successful completion of all tests:
1. Testing on a Linux x86_64/amd64 system is almost certainly required. Various docker images and python modules that are used may not be available for alternative architectures.
2. Availability and operation of a docker daemon to support module operation and test requirements, e.g. test_module_dastardly.py currently assumes that a docker0 interface exists or that IP `172.17.0.1` will be configured on an available interface so that it can instruct the module to connect to that an available IP. The dastardly module itself uses `docker` CLI commands to spin up a container to run dastardly, which will require access to `/var/run/docker.sock` so if not testing as root ensure your unprivileged user can run `docker ps` at minimum, e.g. typically just needs to be part of the docker group.
3. Execution as root/UID=0. Though if you start the testing process as a regular user you will be sudo auth prompted to provide root access.

If you're running a host firewall ensure any containers that are spun up will be able to connect back to the docker host.

Modules such as dastardly will run from within a docker container and they will conduct tests against ports on 172.17.0.1, or whatever IP they detect is on the docker0 interface, which bbot test mock components should be listening on.

For example, this is how dastardly currently runs,

```
bbot  | [VERB] run: docker run --user 0 --rm -v /tmp/.bbot_test/scans/testdastardly_test_3u8hx9ttbl/dastardly:/dastardly -e BURP_START_URL=http://172.17.0.1:5556/ -e BURP_REPORT_FILE_PATH=/dastardly/20240522_0638_21_http-172-17-0-1-5556.xml public.ecr.aws/portswigger/dastardly:latest
```

TCP/5556 in this case has a listener created by the bbot test_module_dastardly.py.

So with ufw or similar, ensure something like this is the case to allow access from containers to your host,

```
root@bbot:~# ip addr show dev docker0
4: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 02:42:20:f1:db:09 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:20ff:fef1:db09/64 scope link 
       valid_lft forever preferred_lft forever
root@bbot:~# ufw allow in on docker0 from 172.17.0.0/16
Rule added
root@bbot:~# ufw status
Status: active

To                      Action      From
--                      ------      ----
22/tcp                  ALLOW       Anywhere                   (log)
Anywhere on docker0     ALLOW       172.17.0.0/16             
22/tcp (v6)             ALLOW       Anywhere (v6)              (log)

root@bbot:~#
```

You can get more specific with firewall rules if desired.

Development and testing from within a dedicated x86_64/amd64 virtual machine running a major Linux distribution such as Debian/Ubuntu/Fedora/etc, with docker-ce installed and dockerd running, and no host firewall; is currently the simplest and cleanest approach with the greatest chance of success.

#### Module Testing Notes

##### Error Messages

`bbot/test/test_step_1/agent_test_scan_bad.py` will generate and ERROR and CRITICAL level output, this is normal as it intentionally triggers problems to catch them, which is the test. e.g. this is normal,

```
bbot/test/test_step_1/test_agent.py::test_agent 
-------------------------------------------------------------------------------------------------------------- live log call ---------------------------------------------------------------------------------------------------------------
ERROR    bbot.scanner:scanner.py:940 Failed to install dependencies for 1 modules: asdf (--force to run module anyway)
CRITICAL bbot.scanner:scanner.py:953 Scan agent_test_scan_bad completed in 0 seconds with status FAILED
PASSED
```

`bbot/test/test_step_1/test_cli.py` currently generates a significant amount of errors that may be confusing, e.g. this is normal,

```
bbot/test/test_step_1/test_cli.py::test_cli 
-------------------------------------------------------------------------------------------------------------- live log call ---------------------------------------------------------------------------------------------------------------
ERROR    bbot.core.agent:agent.py:59 Failed to establish websockets connection to URL "ws://127.0.0.1:8765/control/": [Errno 111] Connect call failed ('127.0.0.1', 8765)
ERROR    bbot.core.agent:agent.py:59 Failed to establish websockets connection to URL "ws://127.0.0.1:8765/control/": [Errno 111] Connect call failed ('127.0.0.1', 8765)
ERROR    asyncio:base_events.py:1758 Task was destroyed but it is pending!
source_traceback: Object created at (most recent call last):
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/bin/pytest", line 8, in <module>
    sys.exit(console_main())
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/_pytest/config/__init__.py", line 197, in console_main
    # to devnull to avoid another BrokenPipeError at shutdown
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/_pytest/config/__init__.py", line 174, in main
    except ValueError:
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/pluggy/_hooks.py", line 501, in __call__
    return self._hookexec(self.name, self._hookimpls.copy(), kwargs, firstresult)
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/pluggy/_manager.py", line 119, in _hookexec
    return self._inner_hookexec(hook_name, methods, kwargs, firstresult)
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/pluggy/_callers.py", line 102, in _multicall
    res = hook_impl.function(*args)
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/_pytest/main.py", line 332, in pytest_cmdline_main
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/_pytest/main.py", line 285, in wrap_session
    config.hook.pytest_keyboard_interrupt(excinfo=excinfo)
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/_pytest/main.py", line 339, in _main
    if session.testsfailed and not session.config.option.continue_on_collection_errors:
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/pluggy/_hooks.py", line 501, in __call__
    return self._hookexec(self.name, self._hookimpls.copy(), kwargs, firstresult)
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/pluggy/_manager.py", line 119, in _hookexec
    return self._inner_hookexec(hook_name, methods, kwargs, firstresult)
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/pluggy/_callers.py", line 102, in _multicall
    res = hook_impl.function(*args)
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/_pytest/main.py", line 364, in pytest_runtestloop
    return False
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/pluggy/_hooks.py", line 501, in __call__
    return self._hookexec(self.name, self._hookimpls.copy(), kwargs, firstresult)
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/pluggy/_manager.py", line 119, in _hookexec
    return self._inner_hookexec(hook_name, methods, kwargs, firstresult)
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/pluggy/_callers.py", line 102, in _multicall
    res = hook_impl.function(*args)
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/_pytest/runner.py", line 115, in pytest_runtest_protocol
    ihook.pytest_runtest_logfinish(nodeid=item.nodeid, location=item.location)
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/_pytest/runner.py", line 134, in runtestprotocol
    reports.append(call_and_report(item, "teardown", log, nextitem=nextitem))
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/_pytest/runner.py", line 239, in call_and_report
    # Exception was expected.
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/_pytest/runner.py", line 340, in from_call
    try:
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/_pytest/runner.py", line 240, in <lambda>
    return False
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/pluggy/_hooks.py", line 501, in __call__
    return self._hookexec(self.name, self._hookimpls.copy(), kwargs, firstresult)
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/pluggy/_manager.py", line 119, in _hookexec
    return self._inner_hookexec(hook_name, methods, kwargs, firstresult)
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/pluggy/_callers.py", line 102, in _multicall
    res = hook_impl.function(*args)
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/_pytest/runner.py", line 172, in pytest_runtest_call
    sys.last_type = type(e)
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/pytest_asyncio/plugin.py", line 436, in runtest
    super().runtest()
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/_pytest/python.py", line 1772, in runtest
    def function(self):
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/pluggy/_hooks.py", line 501, in __call__
    return self._hookexec(self.name, self._hookimpls.copy(), kwargs, firstresult)
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/pluggy/_manager.py", line 119, in _hookexec
    return self._inner_hookexec(hook_name, methods, kwargs, firstresult)
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/pluggy/_callers.py", line 102, in _multicall
    res = hook_impl.function(*args)
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/_pytest/python.py", line 195, in pytest_pyfunc_call
    if hasattr(result, "__await__") or hasattr(result, "__aiter__"):
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/pytest_asyncio/plugin.py", line 897, in inner
    _loop.run_until_complete(task)
  File "/usr/local/lib/python3.10/asyncio/base_events.py", line 636, in run_until_complete
    self.run_forever()
  File "/usr/local/lib/python3.10/asyncio/base_events.py", line 603, in run_forever
    self._run_once()
  File "/usr/local/lib/python3.10/asyncio/base_events.py", line 1901, in _run_once
    handle._run()
  File "/usr/local/lib/python3.10/asyncio/events.py", line 80, in _run
    self._context.run(self._callback, *self._args)
  File "/usr/src/bbot/bbot/test/test_step_1/test_agent.py", line 148, in test_agent
    await agent.start_scan("scan_to_be_cancelled", targets=["127.0.0.1"], modules=["ipneighbor"])
  File "/usr/src/bbot/bbot/agent/agent.py", line 140, in start_scan
    self.task = asyncio.create_task(self._start_scan_task(scan))
  File "/usr/local/lib/python3.10/asyncio/tasks.py", line 337, in create_task
    task = loop.create_task(coro)

%{BREVITY}%

ERROR    bbot.scanner:scanner.py:1069 Error in BaseModule._worker(): /usr/local/lib/python3.10/asyncio/base_events.py:515:_check_closed(): Event loop is closed
ERROR    asyncio:base_events.py:1758 Task was destroyed but it is pending!
source_traceback: Object created at (most recent call last):
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/bin/pytest", line 8, in <module>
    sys.exit(console_main())
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/_pytest/config/__init__.py", line 197, in console_main
    # to devnull to avoid another BrokenPipeError at shutdown
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/_pytest/config/__init__.py", line 174, in main
    except ValueError:
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/pluggy/_hooks.py", line 501, in __call__
    return self._hookexec(self.name, self._hookimpls.copy(), kwargs, firstresult)
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/pluggy/_manager.py", line 119, in _hookexec
    return self._inner_hookexec(hook_name, methods, kwargs, firstresult)
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/pluggy/_callers.py", line 102, in _multicall
    res = hook_impl.function(*args)
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/_pytest/main.py", line 332, in pytest_cmdline_main
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/_pytest/main.py", line 285, in wrap_session
    config.hook.pytest_keyboard_interrupt(excinfo=excinfo)
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/_pytest/main.py", line 339, in _main
    if session.testsfailed and not session.config.option.continue_on_collection_errors:
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/pluggy/_hooks.py", line 501, in __call__
    return self._hookexec(self.name, self._hookimpls.copy(), kwargs, firstresult)
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/pluggy/_manager.py", line 119, in _hookexec
    return self._inner_hookexec(hook_name, methods, kwargs, firstresult)
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/pluggy/_callers.py", line 102, in _multicall
    res = hook_impl.function(*args)
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/_pytest/main.py", line 364, in pytest_runtestloop
    return False
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/pluggy/_hooks.py", line 501, in __call__
    return self._hookexec(self.name, self._hookimpls.copy(), kwargs, firstresult)
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/pluggy/_manager.py", line 119, in _hookexec
    return self._inner_hookexec(hook_name, methods, kwargs, firstresult)
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/pluggy/_callers.py", line 102, in _multicall
    res = hook_impl.function(*args)
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/_pytest/runner.py", line 115, in pytest_runtest_protocol
    ihook.pytest_runtest_logfinish(nodeid=item.nodeid, location=item.location)
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/_pytest/runner.py", line 134, in runtestprotocol
    reports.append(call_and_report(item, "teardown", log, nextitem=nextitem))
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/_pytest/runner.py", line 239, in call_and_report
    # Exception was expected.
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/_pytest/runner.py", line 340, in from_call
    try:
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/_pytest/runner.py", line 240, in <lambda>
    return False
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/pluggy/_hooks.py", line 501, in __call__
    return self._hookexec(self.name, self._hookimpls.copy(), kwargs, firstresult)
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/pluggy/_manager.py", line 119, in _hookexec
    return self._inner_hookexec(hook_name, methods, kwargs, firstresult)
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/pluggy/_callers.py", line 102, in _multicall
    res = hook_impl.function(*args)
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/_pytest/runner.py", line 172, in pytest_runtest_call
    sys.last_type = type(e)
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/pytest_asyncio/plugin.py", line 436, in runtest
    super().runtest()
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/_pytest/python.py", line 1772, in runtest
    def function(self):
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/pluggy/_hooks.py", line 501, in __call__
    return self._hookexec(self.name, self._hookimpls.copy(), kwargs, firstresult)
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/pluggy/_manager.py", line 119, in _hookexec
    return self._inner_hookexec(hook_name, methods, kwargs, firstresult)
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/pluggy/_callers.py", line 102, in _multicall
    res = hook_impl.function(*args)
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/_pytest/python.py", line 195, in pytest_pyfunc_call
    if hasattr(result, "__await__") or hasattr(result, "__aiter__"):
  File "/root/.cache/pypoetry/virtualenvs/bbot-soY1Pi3e-py3.10/lib/python3.10/site-packages/pytest_asyncio/plugin.py", line 897, in inner
    _loop.run_until_complete(task)
  File "/usr/local/lib/python3.10/asyncio/base_events.py", line 636, in run_until_complete
    self.run_forever()
  File "/usr/local/lib/python3.10/asyncio/base_events.py", line 603, in run_forever
    self._run_once()
  File "/usr/local/lib/python3.10/asyncio/base_events.py", line 1901, in _run_once
    handle._run()
  File "/usr/local/lib/python3.10/asyncio/events.py", line 80, in _run
    self._context.run(self._callback, *self._args)
  File "/usr/src/bbot/bbot/agent/agent.py", line 151, in _start_scan_task
    await scan.async_start_without_generator()
  File "/usr/src/bbot/bbot/scanner/scanner.py", line 320, in async_start_without_generator
    async for event in self.async_start():
  File "/usr/src/bbot/bbot/scanner/scanner.py", line 414, in async_start
    self.status = "ABORTED"
  File "/usr/src/bbot/bbot/scanner/scanner.py", line 776, in status
    asyncio.create_task(self.dispatcher.catch(self.dispatcher.on_status, self._status, self.id))
  File "/usr/local/lib/python3.10/asyncio/tasks.py", line 337, in create_task
    task = loop.create_task(coro)
task: <Task pending name='Task-190' coro=<Dispatcher.catch() running at /usr/src/bbot/bbot/scanner/dispatcher.py:29> wait_for=<Future pending cb=[Task.task_wakeup()] created at /usr/local/lib/python3.10/asyncio/base_events.py:429> created at /usr/local/lib/python3.10/asyncio/tasks.py:337>
PASSED                                                                                                                                                                                                                               [  1%]
bbot/test/test_step_1/test_cli.py::test_config_validation PASSED                                                                                                                                                                     [  1%]
bbot/test/test_step_1/test_cli.py::test_module_validation PASSED                                                                                                                                                                     [  2%]
```

The following may generate output similar to the above, e.g. ERROR level events and exception dump type output.
* `bbot/test/test_step_1/test_cloud_helpers.py` 
* `bbot/test/test_step_1/test_python_api.py`
* `bbot/test/test_step_1/test_modules_basic.py`
* `bbot/test/test_step_2/module_tests/test_module_emails.py`
* `bbot/test/test_step_2/module_tests/test_module_git_clone.py`
* `bbot/test/test_step_2/module_tests/test_module_http.py`
* `bbot/test/test_step_2/module_tests/test_module_myssl.py`

Various modules will trigger TRACE events like the below. This is a known Python multiprocessing behaviour issue and while it is confusing it does not affect testing and is unlikely to be the cause of any fatal errors.

```
bbot  | WARNING  bbot.scanner:scanner.py:930 You have enabled custom HTTP headers. These will be attached to all in-scope requests and all requests made by httpx.
bbot  | WARNING  bbot.scanner:scanner.py:930 Failed to set multiprocessing spawn method. This may negatively affect performance.
bbot  | TRACE    bbot.scanner:scanner.py:948 Traceback (most recent call last):
bbot  |   File "/usr/src/bbot/bbot/scanner/scanner.py", line 261, in __init__
bbot  |     mp.set_start_method("spawn")
bbot  |   File "/usr/local/lib/python3.10/multiprocessing/context.py", line 247, in set_start_method
bbot  |     raise RuntimeError('context has already been set')
bbot  | RuntimeError: context has already been set
bbot  |
```

`bbot/test/test_step_2/module_tests/test_module_web_report.py` currently dumps the following which can be ignored.

```
-------------------------------------------------------------------------------------------------------------- live log call ---------------------------------------------------------------------------------------------------------------
CRITICAL bbot.test.webreport:test_module_web_report.py:17 SCAN("testwebreport_test_6k5z6es5ld (SCAN:4d0d7d27bd746f41959c5f1eb858a9436fab73af)", module=TARGET, tags={'in-scope'})
CRITICAL bbot.test.webreport:test_module_web_report.py:17 IP_ADDRESS("127.0.0.1", module=host, tags={'resolved', 'in-scope', 'private', 'ipv4', 'target'})
CRITICAL bbot.test.webreport:test_module_web_report.py:17 URL_UNVERIFIED("http://127.0.0.1:8888/", module=TARGET, tags={'dir', 'in-scope', 'target'})
CRITICAL bbot.test.webreport:test_module_web_report.py:17 HTTP_RESPONSE("{'url': 'http://127.0.0.1:8888/', 'timestamp': '2024-05-23T08:48:01.464240145+10...", module=httpx, tags={'ip-127-0-0-1', 'status-200', 'dir', 'in-scope'})
CRITICAL bbot.test.webreport:test_module_web_report.py:17 URL("http://127.0.0.1:8888/", module=httpx, tags={'ip-127-0-0-1', 'status-200', 'dir', 'in-scope'})
CRITICAL bbot.test.webreport:test_module_web_report.py:17 TECHNOLOGY("{'host': '127.0.0.1', 'technology': 'flask', 'url': 'http://127.0.0.1:8888/'}", module=wappalyzer, tags={'in-scope'})
CRITICAL bbot.test.webreport:test_module_web_report.py:17 TECHNOLOGY("{'host': '127.0.0.1', 'technology': 'iis', 'url': 'http://127.0.0.1:8888/'}", module=wappalyzer, tags={'in-scope'})
CRITICAL bbot.test.webreport:test_module_web_report.py:17 TECHNOLOGY("{'host': '127.0.0.1', 'technology': 'microsoft asp.net', 'url': 'http://127.0.0....", module=wappalyzer, tags={'in-scope'})
CRITICAL bbot.test.webreport:test_module_web_report.py:17 FINDING("{'host': '127.0.0.1', 'description': "Possible secret (PGP private key block): [...", module=secretsdb, tags={'in-scope'})
CRITICAL bbot.test.webreport:test_module_web_report.py:17 TECHNOLOGY("{'host': '127.0.0.1', 'technology': 'google font api', 'url': 'http://127.0.0.1:...", module=wappalyzer, tags={'in-scope'})
CRITICAL bbot.test.webreport:test_module_web_report.py:17 TECHNOLOGY("{'host': '127.0.0.1', 'technology': 'windows server', 'url': 'http://127.0.0.1:8...", module=wappalyzer, tags={'in-scope'})
CRITICAL bbot.test.webreport:test_module_web_report.py:17 FINDING("{'host': '127.0.0.1', 'description': "Possible secret (private_key): ['-----BEGI...", module=secretsdb, tags={'in-scope'})
CRITICAL bbot.test.webreport:test_module_web_report.py:17 FINDING("{'host': '127.0.0.1', 'description': "Possible secret (Generic - 1705): ['BEGIN ...", module=secretsdb, tags={'in-scope'})
CRITICAL bbot.test.webreport:test_module_web_report.py:17 VULNERABILITY("{'host': '127.0.0.1', 'severity': 'CRITICAL', 'description': 'Known Secret Found...", module=badsecrets, tags={'critical', 'in-scope'})
CRITICAL bbot.test.webreport:test_module_web_report.py:17 TECHNOLOGY("{'host': '127.0.0.1', 'technology': 'python', 'url': 'http://127.0.0.1:8888/'}", module=wappalyzer, tags={'in-scope'})
CRITICAL bbot.test.webreport:test_module_web_report.py:17 FINDING("{'host': '127.0.0.1', 'description': "Possible secret (Asymmetric Private Key): ...", module=secretsdb, tags={'in-scope'})
```

You will likely see the follow warnings related to `bbot/test/test_step_2/test_cli.py`, they appear to be normal.

```
home/user/.cache/pypoetry/virtualenvs/bbot-1TJN_DsL-py3.10/lib/python3.10/site-packages/coverage/inorout.py:503: CoverageWarning: Module bbot/test/test_step_2/test_cli.py was never imported. (module-not-imported)
  self.warn(f"Module {pkg} was never imported.", slug="module-not-imported")
/home/user/.cache/pypoetry/virtualenvs/bbot-1TJN_DsL-py3.10/lib/python3.10/site-packages/coverage/control.py:887: CoverageWarning: No data was collected. (no-data-collected)
  self._warn("No data was collected.", slug="no-data-collected")
WARNING: Failed to generate report: No data to report.

/home/user/.cache/pypoetry/virtualenvs/bbot-1TJN_DsL-py3.10/lib/python3.10/site-packages/pytest_cov/plugin.py:352: CovReportWarning: Failed to generate report: No data to report.

  warnings.warn(CovReportWarning(message), stacklevel=1)
```

The final output which indicates full test suite pass is similar to the below,

```
---------- coverage: platform linux, python 3.10.12-final-0 ----------


============================================================================================== 224 passed, 20 warnings in 1492.46s (0:24:52) ===============================================================================================
(bbot-py3.10) user@bbot:~/bbot$
```

## Creating a Module

Writing a module is easy and requires only a basic understanding of Python. It consists of a few steps:

1. Create a new `.py` file in `bbot/modules`
1. At the top of the file, import `BaseModule`
1. Declare a class that inherits from `BaseModule`
   - the class must have the same name as your file (case-insensitive)
1. Define in `watched_events` what type of data your module will consume
1. Define in `produced_events` what type of data your module will produce
1. Define (via `flags`) whether your module is `active` or `passive`, and whether it's `safe` or `aggressive`
1. **Put your main logic in `.handle_event()`**

Here is an example of a simple module that performs whois lookups:

```python title="bbot/modules/whois.py"
from bbot.modules.base import BaseModule

class whois(BaseModule):
    watched_events = ["DNS_NAME"] # watch for DNS_NAME events
    produced_events = ["WHOIS"] # we produce WHOIS events
    flags = ["passive", "safe"]
    meta = {"description": "Query WhoisXMLAPI for WHOIS data"}
    options = {"api_key": ""} # module config options
    options_desc = {"api_key": "WhoisXMLAPI Key"}
    per_domain_only = True # only run once per domain

    base_url = "https://www.whoisxmlapi.com/whoisserver/WhoisService"

    # one-time setup - runs at the beginning of the scan
    async def setup(self):
        self.api_key = self.config.get("api_key")
        if not self.api_key:
            # soft-fail if no API key is set
            return None, "Must set API key"

    async def handle_event(self, event):
        self.hugesuccess(f"Got {event} (event.data: {event.data})")
        _, domain = self.helpers.split_domain(event.data)
        url = f"{self.base_url}?apiKey={self.api_key}&domainName={domain}&outputFormat=JSON"
        self.hugeinfo(f"Visiting {url}")
        response = await self.helpers.request(url)
        if response is not None:
            await self.emit_event(response.json(), "WHOIS", source=event)
```

After saving the module, you can run it with `-m`:

```bash
# run a scan enabling the module in bbot/modules/mymodule.py
bbot -t evilcorp.com -m whois
```

### `handle_event()` and `emit_event()`

The `handle_event()` method is the most important part of the module. By overriding this method, you control what the module does. During a scan, when an [event](./scanning/events.md) from your `watched_events` is encountered (a `DNS_NAME` in this example), `handle_event()` is automatically called with that event as its argument.

The `emit_event()` method is how modules return data. When you call `emit_event()`, it creates an [event](./scanning/events.md) and outputs it, sending it any modules that are interested in that data type.

### `setup()`

A module's `setup()` method is used for performing one-time setup at the start of the scan, like downloading a wordlist or checking to make sure an API key is valid. It needs to return either:

1. `True` - module setup succeeded
2. `None` - module setup soft-failed (scan will continue but module will be disabled)
3. `False` - module setup hard-failed (scan will abort)

Optionally, it can also return a reason. Here are some examples:

```python
async def setup(self):
    if not self.config.get("api_key"):
        # soft-fail
        return None, "No API key specified"

async def setup(self):
    try:
        wordlist = self.helpers.wordlist("https://raw.githubusercontent.com/user/wordlist.txt")
    except WordlistError as e:
        # hard-fail
        return False, f"Error downloading wordlist: {e}"

async def setup(self):
    self.timeout = self.config.get("timeout", 5)
    # success
    return True
```

### Module Config Options

Each module can have its own set of config options. These live in the `options` and `options_desc` attributes on your class. Both are dictionaries; `options` is for defaults and `options_desc` is for descriptions. Here is a typical example:

```python title="bbot/modules/nmap.py"
class nmap(BaseModule):
    # ...
    options = {
        "top_ports": 100,
        "ports": "",
        "timing": "T4",
        "skip_host_discovery": True,
    }
    options_desc = {
        "top_ports": "Top ports to scan (default 100) (to override, specify 'ports')",
        "ports": "Ports to scan",
        "timing": "-T<0-5>: Set timing template (higher is faster)",
        "skip_host_discovery": "skip host discovery (-Pn)",
    }

    async def setup(self):
        self.ports = self.config.get("ports", "")
        self.timing = self.config.get("timing", "T4")
        self.top_ports = self.config.get("top_ports", 100)
        self.skip_host_discovery = self.config.get("skip_host_discovery", True)
```

Once you've defined these variables, you can pass the options via `-c`:

```bash
bbot -m nmap -c modules.nmap.top_ports=250
```

... or via the config:

```yaml title="~/.config/bbot/bbot.yml"
modules:
  nmap:
    top_ports: 250
```

Inside the module, you access them via `self.config`, e.g.:

```python
self.config.get("top_ports")
```

### Module Dependencies

BBOT automates module dependencies with **Ansible**. If your module relies on a third-party binary, OS package, or python library, you can specify them in the `deps_*` attributes of your module.

```python
class MyModule(BaseModule):
    ...
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
```
