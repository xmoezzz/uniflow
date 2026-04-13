from service import Service


def main():
    svc = Service()
    cmd = input()
    return svc.handle(cmd)
