def handle(cmd):
    cb = lambda x: cmd
    return cb("safe")
