import os


class Repo:
    def run(self, cmd):
        return os.system(cmd)


class LoaderDescriptor:
    def __get__(self, obj, owner):
        return obj.repo.run


class Base:
    @property
    def repo(self):
        return Repo()


class Service(Base):
    runner = LoaderDescriptor()

    def handle_super(self, cmd):
        return super().repo.run(cmd)

    def handle_descriptor(self, cmd):
        cb = self.runner
        return cb(cmd)
