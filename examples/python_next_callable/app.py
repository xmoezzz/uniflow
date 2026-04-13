from repo import Registry
import os

def handle(cmd):
    cb = next(Registry())
    return os.system(cb(cmd))
