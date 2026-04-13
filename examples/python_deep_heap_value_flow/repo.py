def load(cmd):
    return cmd

class Node:
    pass

class Service:
    pass


def install_nested(svc):
    svc.inner.cb = load


def pick_field(svc):
    return svc.cb


def pick_index(handlers):
    return handlers[0]
