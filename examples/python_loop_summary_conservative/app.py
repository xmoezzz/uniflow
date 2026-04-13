from repo import Repo

def maybe_repo(items):
    repo = None
    for item in items:
        repo = Repo()
    return repo
