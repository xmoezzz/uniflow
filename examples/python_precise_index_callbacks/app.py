from repo import install, prepare, pick_cb


def handle_direct(cmd):
    handlers = [None, None]
    install(handlers)
    prepare(handlers)
    return handlers[0](cmd)


def handle_returned(cmd):
    handlers = [None, None]
    install(handlers)
    prepare(handlers)
    cb = pick_cb(handlers)
    return cb(cmd)
