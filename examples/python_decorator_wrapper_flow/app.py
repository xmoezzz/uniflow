class Repo:
    def run(self, cmd):
        return cmd

def build(cmd):
    return Repo()

def deco(fn):
    def wrapper(cmd):
        return fn(cmd)
    return wrapper

@deco
def handle(cmd):
    return build(cmd)

def serve(cmd):
    return handle(cmd).run(cmd)
