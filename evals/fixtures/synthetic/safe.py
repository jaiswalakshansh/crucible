# Synthetic fixture (intentionally safe) — parameterized query, no label.
def get_user(db, request):
    uid = request.args.get("id")
    db.execute("SELECT * FROM users WHERE id = ?", (uid,))  # parameterized: safe
    return db.fetchone()
