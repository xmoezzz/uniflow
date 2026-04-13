class Repo:
    def save(self, token, blob):
        return token + str(len(blob))
