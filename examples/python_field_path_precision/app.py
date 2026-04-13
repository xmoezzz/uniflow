from repo import Node, Service, install, load, pick_cb


def handle_local(cmd):
    svc = Service()
    svc.inner = Node()
    svc.inner.cb = load
    cb = pick_cb(svc)
    return cb(cmd)


def handle_interprocedural(cmd):
    svc = Service()
    svc.inner = Node()
    install(svc)
    cb = pick_cb(svc)
    return cb(cmd)
