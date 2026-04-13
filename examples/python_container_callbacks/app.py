from repo import install_defaults


def handle():
    handlers = []
    mapping = {}
    install_defaults(mapping)
    handlers.append(mapping.get("exec"))
    cb = handlers.pop()
    cmd = input()
    return cb(cmd)
