from typing import Generic, TypeVar, TypedDict
from repo import Repo

T = TypeVar("T")

class Payload(TypedDict):
    repo: Repo | None
    count: int

class Box(Generic[T]):
    item: T

    def current(self) -> T:
        return self.item


def handle(box: Box[Repo | None], payload: Payload, ws, cmd: str):
    repo = payload.get("repo")
    if repo is None:
        repo = box.current()
    ws.send_text(cmd)
    return repo.run(cmd)
