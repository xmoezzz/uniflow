from repo import Service


def handle():
    cmd = input()
    svc = Service()
    svc.repo.install()
    return svc.repo.runner.run(cmd)
