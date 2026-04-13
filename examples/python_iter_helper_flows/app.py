from repo import Repo

def build(x):
    return Repo()

def handle_map(cmd):
    repo = next(map(build, [1]))
    return repo.run(cmd)

def handle_sorted(cmd):
    repo = sorted([Repo()])[0]
    return repo.run(cmd)
