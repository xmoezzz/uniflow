from repo import load, alt

def outer(cmd):
    cb = load

    def patch():
        nonlocal cb
        cb = alt

    patch()
    return cb(cmd)
