from repo import Repo

def choose():
    try:
        repo = Repo()
    except Exception as exc:
        repo = Repo()
    return repo
