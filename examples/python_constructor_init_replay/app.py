from repo import Service


def handle():
    cmd = input()
    svc = Service()
    return svc.runner.run(cmd)
