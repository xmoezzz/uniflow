from repo import load, alt, Repo

cb = load

class Service:
    pass

def patch():
    global cb
    cb = alt

def install():
    Service.repo = Repo

patch()
install()

def run(cmd):
    svc = Service()
    return svc.repo().execute(cb(cmd))
