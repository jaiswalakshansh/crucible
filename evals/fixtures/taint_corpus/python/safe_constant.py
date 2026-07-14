def count_users(db):
    # No external input reaches the query.
    return db.execute("SELECT COUNT(*) FROM users")
