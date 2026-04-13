from repo import Service


def handle_super(cmd):
    svc = Service()
    return svc.handle_super(cmd)


def handle_descriptor(cmd):
    svc = Service()
    return svc.handle_descriptor(cmd)
