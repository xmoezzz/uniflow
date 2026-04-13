from fastapi import Depends, Query
from models import Holder, Repo


def get_repo() -> Repo:
    return Repo()


def handle(cmd=Query("ls"), repo=Depends(get_repo)):
    holder = Holder()
    return holder.repo.run(cmd)
