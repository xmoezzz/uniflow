from repo import load, alt

def outer(cmd, enable):
    cb = load

    def patch():
        nonlocal cb
        cb = alt

    if enable:
        patch()
    return cb(cmd)
