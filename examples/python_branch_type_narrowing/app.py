from repo import Repo


def handle(obj, flag):
    if isinstance(obj, Repo):
        repo = obj
    elif flag:
        repo = Repo()
    else:
        repo = Repo()
    return repo.run(input())
