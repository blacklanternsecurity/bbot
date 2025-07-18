import json
from pathlib import Path
from bbot.errors import WordlistError
from bbot.modules.base import BaseModule

# key: <common-protocol-name> value: <legba-protocol-plugin-name>
# List with `legba -L`
PROTOCOL_LEGBA_PLUGIN_MAP = {
    "postgresql": "pgsql",
}


# Maps common protocol names to Legba protocol plugin names
def map_protocol_to_legba_plugin_name(common_protocol_name: str) -> str:
    return PROTOCOL_LEGBA_PLUGIN_MAP.get(common_protocol_name, common_protocol_name)


class legba(BaseModule):
    watched_events = ["PROTOCOL"]
    produced_events = ["FINDING"]
    flags = ["active", "aggressive", "deadly"]
    per_hostport_only = True
    meta = {
        "description": "Credential bruteforcing supporting various services.",
        "created_date": "2025-07-18",
        "author": "@christianfl",
    }
    _module_threads = 25
    scope_distance_modifier = None

    options = {
        "ssh_wordlist": "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt",
        "ftp_wordlist": "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt",
        "telnet_wordlist": "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Default-Credentials/telnet-betterdefaultpasslist.txt",
        "vnc_wordlist": "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Default-Credentials/vnc-betterdefaultpasslist.txt",
        "mssql_wordlist": "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Default-Credentials/mssql-betterdefaultpasslist.txt",
        "mysql_wordlist": "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Default-Credentials/mysql-betterdefaultpasslist.txt",
        "postgresql_wordlist": "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Default-Credentials/postgres-betterdefaultpasslist.txt",
        "concurrency": 3,
        "rate_limit": 3,
    }

    options_desc = {
        "ssh_wordlist": "Wordlist URL for SSH combined username:password wordlist, newline separated",
        "ftp_wordlist": "Wordlist URL for FTP combined username:password wordlist, newline separated",
        "telnet_wordlist": "Wordlist URL for TELNET combined username:password wordlist, newline separated",
        "vnc_wordlist": "Wordlist URL for VNC password wordlist, newline separated",
        "mssql_wordlist": "Wordlist URL for MSSQL combined username:password wordlist, newline separated",
        "mysql_wordlist": "Wordlist URL for MySQL combined username:password wordlist, newline separated",
        "postgresql_wordlist": "Wordlist URL for PostgreSQL combined username:password wordlist, newline separated",
        "concurrency": "Number of concurrent workers, gets overridden for SSH",
        "rate_limit": "Limit the number of requests per second, gets overridden for SSH",
    }

    deps_common = ["rust"]
    deps_ansible = [
        {
            "name": "Install dev tools (Debian)",
            "package": {
                "name": ["pkg-config", "cmake", "libclang-dev", "clang"],
                "state": "present",
            },
            "become": True,
            "when": "ansible_facts['os_family'] == 'Debian'",
            "ignore_errors": True,
        },
        {
            "name": "Install dev tools (Fedora)",
            "package": {
                "name": ["pkgconf-pkg-config", "cmake", "clang-devel", "llvm-devel", "perl-core"],
                "state": "present",
            },
            "become": True,
            "when": "ansible_facts['os_family'] == 'RedHat'",
            "ignore_errors": True,
        },
        {
            "name": "Install dev tools (Arch)",
            "package": {
                "name": ["pkgconf", "cmake", "clang", "openssl"],
                "state": "present",
            },
            "become": True,
            "when": "ansible_facts['os_family'] == 'Archlinux'",
            "ignore_errors": True,
        },
        {
            "name": "Get legba repo",
            "git": {
                "repo": "https://github.com/evilsocket/legba",
                "dest": "#{BBOT_TEMP}/legba/gitrepo",
                "version": "1.1.1",  # Newest stable, 2025-08-25
            },
        },
        {
            # The git repo will be copied because during build, files and subfolders get created. That prevents the Ansible git module to cache the repo.
            "name": "Copy legba repo",
            "copy": {
                "src": "#{BBOT_TEMP}/legba/gitrepo/",
                "dest": "#{BBOT_TEMP}/legba/workdir/",
            },
        },
        {
            "name": "Build legba",
            "command": {
                "chdir": "#{BBOT_TEMP}/legba/workdir",
                "cmd": "cargo build --release",
                "creates": "#{BBOT_TEMP}/legba/workdir/target/release/legba",
            },
            "environment": {"PATH": "{{ ansible_env.PATH }}:{{ ansible_env.HOME }}/.cargo/bin"},
        },
        {
            "name": "Install legba",
            "copy": {
                "src": "#{BBOT_TEMP}/legba/workdir/target/release/legba",
                "dest": "#{BBOT_TOOLS}/",
                "mode": "u+x,g+x,o+x",
            },
        },
    ]

    async def setup(self):
        self.output_dir = Path(self.scan.temp_dir / "legba-output")
        self.helpers.mkdir(self.output_dir)

        return True

    async def filter_event(self, event):
        handled_protocols = ["ssh", "ftp", "telnet", "vnc", "mssql", "mysql", "postgresql"]

        protocol = event.data["protocol"].lower()
        if not protocol in handled_protocols:
            return False, f"service {protocol} is currently not supported or can't be bruteforced by Legba"

        return True

    async def handle_event(self, event):
        host = str(event.host)
        port = str(event.port)
        protocol = event.data["protocol"].lower()

        command_data = await self.construct_command(host, port, protocol)

        if not command_data:
            self.warning(f"Skipping {host}:{port} ({protocol}) due to errors while constructing the command")
            return

        command, output_path = command_data

        await self.run_process(command)

        async for finding_event in self.parse_output(output_path, event):
            await self.emit_event(finding_event)

    async def parse_output(self, output_filepath, event):
        protocol = event.data["protocol"].lower()

        try:
            with open(output_filepath) as file:
                for line in file:
                    # example line (ssh):
                    # {"found_at":"2025-07-18T06:28:08.969812152+01:00","target":"localhost:22","plugin":"ssh","data":{"username":"user","password":"pass"},"partial":false}
                    line = line.strip()

                    try:
                        data = json.loads(line)["data"]
                        username = data.get("username", "")
                        password = data.get("password", "")

                        if username and password:
                            message_addition = f"{username}:{password}"
                        elif username:
                            message_addition = username
                        elif password:
                            message_addition = password
                    except Exception as e:
                        self.warning(f"Failed to parse Legba output ({line}), using raw output instead: {e}")
                        message_addition = f"raw output: {line}"

                    yield self.make_event(
                        {
                            "severity": "CRITICAL",
                            "confidence": "CONFIRMED",
                            "host": str(event.host),
                            "port": str(event.port),
                            "description": f"Valid {protocol} credentials found - {message_addition}",
                        },
                        "FINDING",
                        parent=event,
                    )
        except FileNotFoundError:
            self.info(
                f"Could not open Legba output file {output_filepath}. File is missing if no valid credentials could be found"
            )
        except Exception as e:
            self.warning(f"Error processing Legba output file {output_filepath}: {e}")
        else:
            self.helpers.delete_file(output_filepath)

    async def construct_command(self, host, port, protocol):
        # -C                Combo wordlist delimited by ':'
        # -P                Passwordlist
        # --target          Target (allowed: host, url, IP address, CIDR, @filename)
        # --output-format   Output file format
        # --output          Save results to this file
        # -Q                Do not report statistics
        #
        # --wait            Wait time in milliseconds per login attempt
        # --rate-limit      Limit the number of requests per second
        # --concurrency     Number of concurrent workers

        # Example command to bruteforce SSH:
        #
        # legba ssh -C combolist.txt --target 127.0.0.1:22 --output-format jsonl --output out.txt -Q --wait 4000 --rate-limit 1 --concurrency 1

        try:
            wordlist_path = await self.helpers.wordlist(self.config.get(f"{protocol}_wordlist"))
        except WordlistError as e:
            self.warning(f"Error retrieving wordlist for protocol {protocol}: {e}")
            return None
        except Exception as e:
            self.warning(f"Unexpected error during wordlist loading for protocol {protocol}: {e}")
            return None

        protocol_plugin_name = map_protocol_to_legba_plugin_name(protocol)
        output_path = Path(self.output_dir) / f"{host}_{port}.json"

        cmd = [
            "legba",
            protocol_plugin_name,
        ]

        if protocol == "vnc":
            # use only passwords, not combinations
            cmd += ["-P"]

        else:
            # use combinations
            cmd += ["-C"]

        # wrap IPv6 addresses in square brackets
        if self.helpers.is_ip(host, version=6):
            host = f"[{host}]"

        cmd += [
            wordlist_path,
            "--target",
            f"{host}:{port}",
            "--output-format",
            "jsonl",
            "--output",
            output_path,
            "-Q",
        ]

        if protocol == "ssh":
            # With OpenSSH 9.8, the sshd_config option "PerSourcePenalties" was introduced (on by default)
            # The penalty "authfail" defaults to 5 seconds, so bruteforcing fast will block access.
            # Legba is not able to check that by itself, so the wait time is set to 5 s, rate limit to 1 and concurrency to 1 with SSH.
            # See https://www.openssh.com/txt/release-9.8
            cmd += [
                "--wait",
                "5000",
                "--rate-limit",
                "1",
                "--concurrency",
                "1",
            ]
        else:
            cmd += ["--rate-limit", self.config.rate_limit, "--concurrency", self.config.concurrency]

        return cmd, output_path
