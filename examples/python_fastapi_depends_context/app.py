from fastapi import Depends
from repo import get_repo


class State:
    def get(self, key):
        return key


class Request:
    def __init__(self):
        self.state = State()


def handle(request: Request, repo=Depends(get_repo)):
    cmd = request.state.get("cmd")
    return repo.run(cmd)
