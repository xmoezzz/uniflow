import importlib


def handle():
    mod = importlib.import_module("repo")
    cb = mod.load
    return cb(input())
