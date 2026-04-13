from repo import Service, load


def handle_via_list(cmd):
    handlers = [load]
    return handlers[0](cmd)


def handle_via_field(cmd):
    svc = Service()
    svc.cb = load
    return svc.cb(cmd)
