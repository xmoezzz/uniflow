from dataclasses import asdict
from flask import session
from repo import Repo

class Payload:
    repo: Repo
    items: list[Repo]
    payload: dict[str, Repo]

    def __init__(self, repo):
        self.repo = repo
        self.items = [repo]
        self.payload = {"main": repo}

    def model_dump(self):
        return {"repo": self.repo, "items": self.items, "payload": self.payload}


def handle(cmd):
    repo = Repo()
    user = session.get("user")
    payload = Payload(repo)
    data = payload.model_dump()
    shadow = asdict(payload)
    return data["repo"].run(user or cmd), shadow["repo"].run(cmd)
