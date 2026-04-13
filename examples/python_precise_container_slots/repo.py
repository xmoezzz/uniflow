import os


def run(cmd):
    return os.system(cmd)


def noop(cmd):
    return 0


def pick(mapping):
    return mapping["cb"]
