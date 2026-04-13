from typing import TypedDict
from fastapi import File, Form, UploadFile
from repo import Repo

RequestDoc = TypedDict("RequestDoc", {"name": str, "token": str})

repo = Repo()

async def handle(upload: UploadFile = File(...), token: str = Form(...)):
    payload: RequestDoc = {"name": upload.filename, "token": token}
    content = await upload.read()
    return repo.save(payload["token"], content)
