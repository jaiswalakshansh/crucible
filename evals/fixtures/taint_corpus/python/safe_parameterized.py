def get_user(db, request):
    uid = request.args.get("id")
    # Parameterized query: the query string is constant, so this is safe.
    return db.execute("SELECT * FROM users WHERE id = ?", (uid,))
