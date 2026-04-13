from typing import cast
from repo import Repo


def handle(obj):
    repo = cast(Repo, obj)
    assert isinstance(repo, Repo)
    return repo.run(input())
