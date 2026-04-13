from repo import Repo, load
import os

globals().update({"load_alias": load})

class Service:
    pass

vars(Service).update(repo=Repo())

def handle(cmd):
    cb = globals()["load_alias"]
    return os.system(cb(Service.repo.run(cmd)))
