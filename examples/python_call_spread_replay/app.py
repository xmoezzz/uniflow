from repo import Service, install, install_kw


def handle_star():
    cmd = input()
    svc = Service()
    args = (svc,)
    install(*args)
    return svc.repo.run(cmd)


def handle_starstar():
    cmd = input()
    svc = Service()
    kwargs = {"service": svc}
    install_kw(**kwargs)
    return svc.repo.run(cmd)
