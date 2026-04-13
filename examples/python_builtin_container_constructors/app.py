import os


def load(cmd):
    return os.system(cmd)


def noop(cmd):
    return cmd


def handle():
    handlers = [noop, load]
    alias = list(handlers)
    cb = alias[1]
    mapping = dict(cb=load)
    return cb(input()) + mapping["cb"](input())
