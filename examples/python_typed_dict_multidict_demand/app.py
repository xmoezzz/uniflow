from typing import TypedDict


class Payload(TypedDict):
    id: int
    token: str


class Repo:
    def save(self, token: str) -> str:
        return token


def handle(payload: Payload, request, repo: Repo):
    first = request.query_params.get("id", "0")
    headers = request.headers.items()
    pairs = payload.items()
    token = repo.save(payload["token"])
    return first, headers, pairs, token
