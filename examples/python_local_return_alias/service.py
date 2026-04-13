from db import Repo


def build_repo():
    current = Repo()
    return current


class Service:
    def __init__(self):
        repo = build_repo()
        setattr(self, "repo", repo)

    def handle(self, cmd):
        current = self.repo
        return current.run(cmd)
