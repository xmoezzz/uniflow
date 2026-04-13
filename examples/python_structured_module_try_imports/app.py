try:
    from repo import load as cb
except ImportError:
    from repo import load as cb

def handle(cmd):
    return cb(cmd)
