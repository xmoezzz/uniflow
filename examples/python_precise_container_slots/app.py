from repo import noop, pick, run


def handle():
    handlers = [noop, run]
    alias = handlers
    mapping = {"safe": alias[0]}
    mapping["cb"] = alias[1]
    cb = pick(mapping)
    cmd = input()
    return cb(cmd)
