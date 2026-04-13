def load(cmd):
    return cmd


def noop(cmd):
    return "safe"


def install(handlers):
    handlers[1] = load


def prepare(handlers):
    handlers[0] = noop


def pick_cb(handlers):
    return handlers[0]
