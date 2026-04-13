from typing import Protocol, TypeVar, TypedDict
from fastapi import Query
from sqlalchemy.orm import Mapped, relationship
from repo import Repo, User

T = TypeVar("T")

class Reader(Protocol[T]):
    def get(self) -> T:
        raise NotImplementedError

class Team:
    owner: Mapped[User]
    members = relationship("User")

class Payload(TypedDict):
    id: int
    name: str

repo = Repo()

def handle(user_id: int = Query(...)):
    payload: Payload = {"id": user_id, "name": "guest"}
    team = Team()
    _owner = team.owner
    _members = team.members
    return repo.save(payload.get("id"))
