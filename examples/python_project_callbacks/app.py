from repo import Service, dispatch, load


def handle(cmd):
    bound = Service().run
    left = dispatch(load, cmd)
    right = dispatch(bound, cmd)
    return left + right
