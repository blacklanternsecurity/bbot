import re
from bbot.modules.base import BaseModule
from bbot.errors import WordlistError


class medusa(BaseModule):
    watched_events = ["PROTOCOL"]
    produced_events = ["VULNERABILITY"]
    flags = ["active", "aggressive", "deadly"]
    per_host_only = True
    meta = {
        "description": "Medusa SNMP bruteforcing with v1, v2c and R/W check.",
        "created_date": "2025-05-16",
        "author": "@christianfl",
    }
    scope_distance_modifier = None

    options = {
        "snmp_wordlist": "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/SNMP/common-snmp-community-strings.txt",
        "snmp_versions": ["1", "2C"],  # Only 1 and 2C are available with medusa 2.3.
        "wait_microseconds": 200,
        "timeout_s": 5,
        "threads": 5,
    }

    options_desc = {
        "snmp_wordlist": "Wordlist url for SNMP community strings, newline separated (default https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/SNMP/snmp.txt)",
        "snmp_versions": "List of SNMP versions to attempt against the SNMP server (default ['1', '2C'])",
        "wait_microseconds": "Wait time after every SNMP request in microseconds (default 200)",
        "timeout_s": "Wait time for the SNMP response(s) once at the end of all attempts (default 5)",
        "threads": "Number of communities to be tested concurrently (default 5)",
    }

    deps_ansible = [
        {
            "name": "Install build dependencies",
            "package": {
                "name": [
                    "autoconf",
                    "automake",
                    "libtool",
                    "gcc",
                    "make",
                ],
                "state": "present",
            },
            "become": True,
            "ignore_errors": True,
        },
        {
            "name": "Get medusa repo",
            "git": {
                "repo": "https://github.com/jmk-foofus/medusa",
                "dest": "#{BBOT_TEMP}/medusa/gitrepo",
                "version": "2.3",  # Newest stable, 2025-05-15
            },
        },
        {
            # The git repo will be copied because during build, files and subfolders get created. That prevents the Ansible git module to cache the repo.
            "name": "Copy medusa repo",
            "copy": {
                "src": "#{BBOT_TEMP}/medusa/gitrepo/",
                "dest": "#{BBOT_TEMP}/medusa/workdir/",
            },
        },
        {
            "name": "Build medusa: autoreconf",
            "command": {
                "chdir": "#{BBOT_TEMP}/medusa/workdir",
                "cmd": "autoreconf -f -i",
            },
        },
        {
            "name": "Build medusa: configure",
            "command": {
                "chdir": "#{BBOT_TEMP}/medusa/workdir",
                "cmd": "./configure --prefix=#{BBOT_TEMP}/medusa/build",
            },
        },
        {
            "name": "Build medusa: make",
            "command": {
                "chdir": "#{BBOT_TEMP}/medusa/workdir",
                "cmd": "make",
            },
        },
        {
            "name": "Build medusa: make install",
            "command": {
                "chdir": "#{BBOT_TEMP}/medusa/workdir",
                "cmd": "make install",
                "creates": "#{BBOT_TEMP}/medusa/build/bin/medusa",
            },
        },
        {
            "name": "Install medusa",
            "copy": {
                "src": "#{BBOT_TEMP}/medusa/build/bin/medusa",
                "dest": "#{BBOT_TOOLS}/",
                "mode": "u+x,g+x,o+x",
            },
        },
    ]

    async def setup(self):
        # Try to cache wordlist
        try:
            self.snmp_wordlist_path = await self.helpers.wordlist(self.config.get("snmp_wordlist"))
        except WordlistError as e:
            return False, f"Error retrieving wordlist: {e}"

        self.password_match_regex = re.compile(r"Password:\s*(\S+)")
        self.success_indicator_match_regex = re.compile(r"\[([^\]]+)\]\s*$")

        return True

    async def filter_event(self, event):
        handled_protocols = ["snmp"]  # Could be extended later

        protocol = event.data["protocol"].lower()
        if not protocol in handled_protocols:
            return False, f"service {protocol} is currently not supported. Only SNMP."

        return True

    async def handle_event(self, event):
        host = str(event.host)
        port = str(event.port)
        protocol = event.data["protocol"].lower()

        if protocol == "snmp":
            snmp_versions = self.config.get("snmp_versions")

            # Medusa must be called for each SNMP version separately after each run finished.
            for snmp_version in snmp_versions:
                command = await self.construct_command(host, port, protocol, snmp_version)

                result = await self.run_process(command)

                if result.stderr:
                    # Medusa outputs to stderr if a readonly community was found in WRITE mode
                    # That's intended behavior
                    self.info(f"Medusa stderr: {result.stderr}")

                async for message in self.parse_output(result.stdout, snmp_version):
                    vuln_event = self.create_vuln_event("CRITICAL", message, event)
                    await self.emit_event(vuln_event)

        # else: Medusa supports various protocols which could in theory be implemented later on.

    async def parse_output(self, output, protocol_version):
        for line in output.splitlines():
            # Print original Medusa output
            self.info(line)

            if "FOUND" in line:
                # Some credential was guessed
                password_match = self.password_match_regex.search(line)
                password = password_match.group(1) if password_match else None

                success_indicator_match = self.success_indicator_match_regex.search(line)
                success_indicator = success_indicator_match.group(1) if success_indicator_match else None

                # Medusa in WRITE mode shows "ERROR" if a readonly community was found. Replace with "READ"
                mode = "R/W" if success_indicator == "success" else "READ" if success_indicator == "ERROR" else "MODE?"

                message = f"VALID [SNMPV{protocol_version}] CREDENTIALS FOUND: {password} [{mode}]"

                yield message

    async def construct_command(self, host, port, protocol, protocol_version):
        # -b                Suppress startup banner
        # -v                Set verbosity level (4 = Show only errors and credentials)
        # -R                Number of attempted retries
        # -M                Medusa module to execute (SNMP)
        # -T                Number of concurrent hosts
        # -t                Number of concurrent login attempts
        # -h                Target hostname or ip address
        # -u                Username to test (Empty for SNMP)
        # -P                Wordlist for passwords
        # -m                Module specific parameters:
        #   TIMEOUT:<number>        Sets the number of seconds to wait for the UDP responses (default: 5 sec).
        #   SEND_DELAY:<number>     Sets the number of microseconds to wait between sending queries (default: 200 usec).
        #   VERSION:<1|2C>          Set the SNMP client version.
        #   ACCESS:<READ|WRITE>     Set level of access to test for with the community string. ("WRITE" does include "READ")

        # Example command to bruteforce SNMP:
        #
        # medusa -b -v 4 -R 1 -M snmp -T 1 -t 1 -h 127.0.0.1 -u '' -P communities.txt -m VERSION:2C -m SEND_DELAY:1000000 -m ACCESS:WRITE -m TIMEOUT:10

        cmd = [
            "medusa",
            "-b",
            "-v",
            4,
            "-R",
            1,
            "-M",
            protocol,
            "-T",
            1,
            "-t",
            self.config.get("threads"),
            "-h",
            host,
            "-u",
            "''",
            "-P",
            self.snmp_wordlist_path,
            "-m",
            f"VERSION:{protocol_version}",
            "-m",
            f"SEND_DELAY:{self.config.get('wait_microseconds')}",
            "-m",
            "ACCESS:WRITE",
            "-m",
            f"TIMEOUT:{self.config.get('timeout_s')}",
        ]

        return cmd

    def create_vuln_event(self, severity, description, source_event):
        host = str(source_event.host)
        port = str(source_event.port)

        return self.make_event(
            {
                "severity": severity,
                "host": host,
                "port": port,
                "description": description,
            },
            "VULNERABILITY",
            source_event,
        )
