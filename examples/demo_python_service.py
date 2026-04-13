from security import escape_sql

def handle(request, db):
    query = request.get_parameter("q")
    safe = escape_sql(query)
    db.execute(safe)
