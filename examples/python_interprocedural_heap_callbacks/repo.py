def load(cmd):
    return cmd


class Service:
    pass


def install(svc):
    svc.cb = load


def prepare(svc):
    svc.cb = load
    return svc


def install_handlers(handlers):
    handlers[0] = load
