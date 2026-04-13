from repo import Service


def handle_instance():
    cmd = input()
    svc = Service()
    svc.install()
    return svc.runner.run(cmd)


def handle_class():
    cmd = input()
    Service.install_shared()
    return Service.shared.run(cmd)
