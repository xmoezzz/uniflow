import os

class Loader:
    def __call__(self, cmd):
        return os.system(cmd)


def handle():
    loader = Loader()
    return loader(input())
