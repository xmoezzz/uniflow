import os

def run(cmd):
    return os.system(cmd)


def install_defaults(mapping):
    mapping.setdefault("exec", run)
