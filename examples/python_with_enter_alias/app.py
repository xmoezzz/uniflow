from repo import Repo


class RepoManager:
    def __enter__(self):
        return Repo()

    def __exit__(self, exc_type, exc, tb):
        return None


def handle():
    with RepoManager() as repo:
        return repo.run(input())
