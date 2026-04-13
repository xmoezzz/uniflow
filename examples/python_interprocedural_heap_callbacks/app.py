from repo import Service, install, install_handlers, prepare


def handle_field(cmd):
    svc = Service()
    install(svc)
    return svc.cb(cmd)


def handle_returned_alias(cmd):
    svc = Service()
    ready = prepare(svc)
    return ready.cb(cmd)


def handle_index(cmd):
    handlers = [None]
    install_handlers(handlers)
    return handlers[0](cmd)
