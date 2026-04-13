from .repo import Handler, Node, PendingRepo, Repo


def use_handler(handler: Handler, name: str):
    return handler(name)


def handle(cache, handler: Handler, pending: PendingRepo):
    repo = Repo()
    current = cache.get("repo", repo)
    children = Node().children
    return use_handler(handler, current.clone())
