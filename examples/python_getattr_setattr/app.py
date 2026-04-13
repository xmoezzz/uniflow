import os


class Repo:
    def run(self, cmd):
        return os.system(cmd)


class Service:
    pass


def handle():
    svc = Service()
    setattr(svc, "repo", Repo())
    return getattr(svc, "repo").run(input())
