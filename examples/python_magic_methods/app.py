import os


class MagicBox:
    def __init__(self):
        self.mapping = {}
        self.handlers = []

    def __setitem__(self, key, value):
        self.mapping[key] = value
        self.handlers = [value]

    def __getitem__(self, key):
        return self.mapping[key]

    def __iter__(self):
        return self.handlers


def run(cmd):
    return os.system(cmd)


def handle_indexed():
    box = MagicBox()
    box["run"] = run
    cb = box["run"]
    return cb(input())


def handle_iterated():
    box = MagicBox()
    box["run"] = run
    for cb in box:
        return cb(input())
