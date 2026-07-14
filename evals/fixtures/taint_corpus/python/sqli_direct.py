def get_user(db, request):
    return db.execute("SELECT * FROM users WHERE id = " + request.args.get("id"))  # sink
