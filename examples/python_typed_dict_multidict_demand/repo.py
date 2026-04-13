class QueryParams:
    def get(self, name, default=None):
        return default


class Headers:
    def items(self):
        return []


class Request:
    def __init__(self):
        self.query_params = QueryParams()
        self.headers = Headers()
