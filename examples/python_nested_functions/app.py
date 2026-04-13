def choose(cmd):
    def inner(x):
        return cmd
    return inner


def handle(cmd):
    cb = choose(cmd)
    print(cb("safe"))
