import os


class Box:
    def __init__(self):
        self.mapping = {}

    def __setitem__(self, key, value):
        self.mapping[key] = value

    def __getitem__(self, key):
        return self.mapping[key]

    def __delitem__(self, key):
        if key in self.mapping:
            del self.mapping[key]


def load(cmd):
    return os.system(cmd)


def configure_then_clear(cmd):
    box = Box()
    box["run"] = load
    del box["run"]
    box["run"] = load
    cb = box["run"]
    return cb(cmd)
