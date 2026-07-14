def get_user(db, request):
    uid = request.args.get("id")
    query = "SELECT * FROM users WHERE id = " + uid
    return db.execute(query)  # sink
