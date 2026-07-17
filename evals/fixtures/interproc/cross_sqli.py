def handler(request):
    user_id = request.args.get("id")
    return fetch(user_id)


def fetch(uid):
    return db.execute("SELECT * FROM users WHERE id = " + uid)  # sink (line 7)
