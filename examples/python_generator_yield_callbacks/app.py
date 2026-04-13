from repo import callbacks

def handle(cmd):
    cb = next(callbacks())
    return cb(cmd)
