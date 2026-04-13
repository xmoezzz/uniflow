from service import get_db


def run(request):
    sql = request.values.get("q")
    return get_db().execute(sql)
