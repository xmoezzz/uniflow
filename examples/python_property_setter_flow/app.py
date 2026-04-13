import os


class Repo:
    def run(self, cmd):
        return os.system(cmd)


class Service:
    def __init__(self):
        self._repo = None

    @property
    def repo(self):
        return self._repo

    @repo.setter
    def repo(self, value):
        self._repo = value


def handle():
    svc = Service()
    svc.repo = Repo()
    return svc.repo.run(input())
