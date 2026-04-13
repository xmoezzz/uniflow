from repo import Repo, load

class Service:
    pass

if flag:
    cb = load
    Service.repo = Repo()
else:
    cb = load
    Service.repo = Repo()

def handle(cmd):
    return cb(Service.repo.run(cmd))
