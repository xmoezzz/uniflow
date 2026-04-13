def load(cmd):
    return cmd

class Node:
    pass

class Service:
    pass


def install(svc):
    svc.inner.cb = load


def pick_cb(svc):
    return svc.inner.cb
