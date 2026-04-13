from repo import Node, Service, install_nested, load, pick_field, pick_index


def handle_nested(cmd):
    svc = Service()
    svc.inner = Node()
    install_nested(svc)
    return svc.inner.cb(cmd)


def handle_pick_field(cmd):
    svc = Service()
    svc.cb = load
    cb = pick_field(svc)
    return cb(cmd)


def handle_pick_index(cmd):
    handlers = [load]
    cb = pick_index(handlers)
    return cb(cmd)
