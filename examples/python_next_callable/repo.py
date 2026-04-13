def load(cmd):
    return cmd

class Registry:
    def __iter__(self):
        return self

    def __next__(self):
        return load
