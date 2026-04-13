from repo import Service


def handle(cmd):
    svc = Service()
    return svc.repo.run(cmd)
