# Annotated test file for python-subprocess-shell-true. Deliberately vulnerable: do not run.
import subprocess


def ping(host):
    cmd = "ping -c 1 " + host
    # ruleid: python-subprocess-shell-true
    subprocess.run(cmd, shell=True)


def archive(name):
    # ruleid: python-subprocess-shell-true
    return subprocess.check_output(f"tar czf {name}.tgz {name}", shell=True)


def ping_list(host):
    # ok: python-subprocess-shell-true
    subprocess.run(["ping", "-c", "1", host])


def constant():
    # ok: python-subprocess-shell-true
    subprocess.call("ls -l /tmp", shell=True)
