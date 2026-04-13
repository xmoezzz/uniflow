import os

class Repo:
    def run(self, cmd):
        return os.system(cmd)

class Service:
    pass


def install(service):
    service.repo = Repo()


def install_kw(*, service):
    service.repo = Repo()
