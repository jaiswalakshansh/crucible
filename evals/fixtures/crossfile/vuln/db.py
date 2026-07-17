def run_query(q):
    return conn.execute("SELECT * FROM users WHERE id = " + q)  # sink (line 2)
