from repo import AsyncManager, AsyncRegistry
import os

async def handle(cmd):
    async with AsyncManager() as repo:
        first = repo.run(cmd)
    async for cb in AsyncRegistry():
        return os.system(cb(first))
    return first
