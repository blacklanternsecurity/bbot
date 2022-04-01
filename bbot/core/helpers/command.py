import subprocess
import logging

log = logging.getLogger("bbot.core.helpers.command")


def execute_command_live(self, cmdargs):

    #   cmd = ['/bin/ping','-c','8','google.com']

    log.debug(f"Executing command {' '.join(cmdargs)}")

    # fulloutput = b""

    with subprocess.Popen(
        cmdargs, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    ) as p:
        for line in io.TextIOWrapper(p.stdout, encoding="utf-8", errors="ignore"):
            yield line
    #    char = p.stdout.read(1)


#     while char != b'':
#         char = p.stdout.read(1)
#         fulloutput += char

# log.debug(f"command completed")
# return fulloutput.decode()


def execute_command(self, cmdargs):

    #   cmd = ['/bin/ping','-c','8','google.com']
    log.debug(f"Executing command {' '.join(cmdargs)}")
    result = subprocess.run(
        cmdargs, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )
    return result.stdout
