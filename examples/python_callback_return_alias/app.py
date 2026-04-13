from repo import Service, choose, load


def handle_returned_callback(cmd):
    cb = choose()
    return cb(cmd)


def handle_alias_field(cmd):
    svc = Service()
    alias = svc
    alias.cb = load
    return svc.cb(cmd)
