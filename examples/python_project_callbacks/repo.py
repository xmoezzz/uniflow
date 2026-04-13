def load(cmd):
    return cmd


def dispatch(cb, cmd):
    return cb(cmd)


class Service:
    def run(self, cmd):
        return cmd
