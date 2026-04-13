from repo import Repo


def load(cmd):
    return cmd


globals()["load_alias"] = load


class Service:
    def __init__(self):
        self.__dict__["repo"] = Repo()

    def handle(self):
        cb = globals()["load_alias"]
        repo = vars(self)["repo"]
        return repo.run(cb(input()))
