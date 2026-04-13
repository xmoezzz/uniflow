from repo import Service, install


def handle():
    cmd = input()
    svc = Service()
    install(svc)
    return svc.runner.run(cmd)
