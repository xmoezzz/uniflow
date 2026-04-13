def load(cmd):
    return cmd

class Repo:
    def run(self, cmd):
        return cmd

class AsyncManager:
    async def __aenter__(self):
        return Repo()

    async def __aexit__(self, exc_type, exc, tb):
        return None

class AsyncRegistry:
    def __aiter__(self):
        return self

    async def __anext__(self):
        return load
