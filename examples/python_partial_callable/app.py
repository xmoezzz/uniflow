import os
from functools import partial


def load(cmd):
    return os.system(cmd)


def handle():
    cb = partial(load)
    return cb(input())
