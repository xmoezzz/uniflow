from repo import load

def handle(cmd):
    try:
        cb = load
    except Exception as exc:
        cb = load
    finally:
        final_cb = cb
    return final_cb(cmd)
