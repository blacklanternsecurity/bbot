from .base import ModuleTestBase

smuggler_text = r"""
              ______ _              
     / _____)                       | |             
    ( (____  ____  _   _  ____  ____| | _____  ____ 
     \____ \|    \| | | |/ _  |/ _  | || ___ |/ ___)
     _____) ) | | | |_| ( (_| ( (_| | || ____| |    
    (______/|_|_|_|____/ \___ |\___ |\_)_____)_|    
                        (_____(_____|               

         @defparam v1.1

    [+] URL        : http://127.0.0.1:8888
    [+] Method     : POST
    [+] Endpoint   : /
    [+] Configfile : default.py
    [+] Timeout    : 5.0 seconds
    [+] Cookies    : 1 (Appending to the attack)                   
    [nameprefix1]  : Checking TECL...                
    [nameprefix1]  : Checking CLTE...             
    [nameprefix1]  : OK (TECL: 0.61 - 405) (CLTE: 0.62 - 405)       
    [tabprefix1]   : Checking TECL...git 
    [tabprefix1]   : Checking CLTE...          
    [tabprefix1]   : Checking TECL...                 
    [tabprefix1]   : Checking CLTE...
    [tabprefix1]   : Checking TECL...
    [tabprefix1]   : Checking CLTE...
    [tabprefix1]   : Potential CLTE Issue Found - POST @ http://127.0.0.1:8888 - default.py
    [CRITICAL]     : CLTE Payload: /home/user/.bbot/tools/smuggler/payloads/http_127.0.0.1_net_CLTE_tabprefix1.txt URL: http://127.0.0.1:8888/
    """


class TestSmuggler(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "smuggler"]

    async def setup_after_prep(self, module_test):
        old_run_live = module_test.scan.helpers.run_live

        async def smuggler_mock_run_live(*command, **kwargs):
            if not "smuggler" in command[0][1]:
                async for l in old_run_live(*command, **kwargs):
                    yield l
            else:
                for line in smuggler_text.splitlines():
                    yield line

        module_test.monkeypatch.setattr(module_test.scan.helpers, "run_live", smuggler_mock_run_live)

        request_args = {"uri": "/"}
        respond_args = {"response_data": "alive"}
        module_test.set_expect_requests(request_args, respond_args)

    def check(self, module_test, events):
        assert any(
            e.type == "FINDING"
            and "[HTTP SMUGGLER] [Potential CLTE Issue Found] Technique:     [tabprefix1]" in e.data["description"]
            for e in events
        ), "Failed to parse mocked command output"
