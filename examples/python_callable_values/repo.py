def load(cmd):
    return cmd

class Service:
    def handle(self, cmd):
        self.cb = load
        return self.cb(cmd)
