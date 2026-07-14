def get_user(db, request):
    # Coercing to int neutralizes the taint for a SQL context.
    uid = int(request.args.get("id"))
    return db.execute("SELECT * FROM users WHERE id = " + str(uid))
