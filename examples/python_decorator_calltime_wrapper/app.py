from repo import Repo

class Service:
    pass

def deco(fn):
    def wrapper(svc, cmd):
        svc.repo = Repo()
        return fn(svc, cmd)
    return wrapper

@deco
def handle(svc, cmd):
    return cmd

def call(cmd):
    svc = Service()
    handle(svc, cmd)
    return svc.repo.run(cmd)
