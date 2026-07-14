# Synthetic fixture (intentionally vulnerable) — used only to exercise the eval
# code path. The labeled line below is the sink.
def get_user(db, request):
    uid = request.args.get("id")
    db.execute("SELECT * FROM users WHERE id = " + uid)  # line 4: SQL injection sink
    return db.fetchone()
