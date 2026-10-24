DEP_DOCKER = [
    {
        "name": "Check if Docker is already installed",
        "command": "docker --version",
        "register": "docker_installed",
        "ignore_errors": True,
    },
    {
        "name": "Install Docker (Non-Debian)",
        "package": {"name": "docker", "state": "present"},
        "become": True,
        "when": "ansible_facts['os_family'] != 'Debian' and docker_installed.rc != 0",
    },
    {
        "name": "Install Docker (Debian)",
        "package": {
            "name": "docker.io",
            "state": "present",
        },
        "become": True,
        "when": "ansible_facts['os_family'] == 'Debian' and docker_installed.rc != 0",
    },
]

DEP_MASSCAN = [
    {
        "name": "install os deps (Debian)",
        "package": {"name": ["gcc", "git", "make", "libpcap0.8-dev"], "state": "present"},
        "become": True,
        "when": "ansible_facts['os_family'] == 'Debian'",
        "ignore_errors": True,
    },
    {
        "name": "install dev tools (Non-Debian)",
        "package": {"name": ["gcc", "git", "make", "libpcap"], "state": "present"},
        "become": True,
        "when": "ansible_facts['os_family'] != 'Debian'",
        "ignore_errors": True,
    },
    {
        "name": "Download masscan source code",
        "git": {
            "repo": "https://github.com/robertdavidgraham/masscan.git",
            "dest": "#{BBOT_TEMP}/masscan",
            "single_branch": True,
            "version": "master",
        },
    },
    {
        "name": "Build masscan",
        "command": {
            "chdir": "#{BBOT_TEMP}/masscan",
            "cmd": "make -j",
            "creates": "#{BBOT_TEMP}/masscan/bin/masscan",
        },
    },
    {
        "name": "Install masscan",
        "copy": {"src": "#{BBOT_TEMP}/masscan/bin/masscan", "dest": "#{BBOT_TOOLS}/", "mode": "u+x,g+x,o+x"},
    },
]

DEP_JAVA = [
    {
        "name": "Check if Java is installed",
        "command": "which java",
        "register": "java_installed",
        "ignore_errors": True,
    },
    {
        "name": "Install latest JRE (Debian)",
        "package": {"name": ["default-jre"], "state": "present"},
        "become": True,
        "when": "ansible_facts['os_family'] == 'Debian' and java_installed.rc != 0",
    },
    {
        "name": "Install latest JRE (Arch)",
        "package": {"name": ["jre-openjdk"], "state": "present"},
        "become": True,
        "when": "ansible_facts['os_family'] == 'Archlinux' and java_installed.rc != 0",
    },
    {
        "name": "Install latest JRE (Fedora)",
        "package": {"name": ["which", "java-latest-openjdk-headless"], "state": "present"},
        "become": True,
        "when": "ansible_facts['os_family'] == 'RedHat' and java_installed.rc != 0",
    },
    {
        "name": "Install latest JRE (Alpine)",
        "package": {"name": ["openjdk11"], "state": "present"},
        "become": True,
        "when": "ansible_facts['os_family'] == 'Alpine' and java_installed.rc != 0",
    },
]

# shared module dependencies -- docker, java, etc.
SHARED_DEPS = {}
for var, val in list(locals().items()):
    if var.startswith("DEP_") and isinstance(val, list):
        var = var.split("_", 1)[-1].lower()
        SHARED_DEPS[var] = val
