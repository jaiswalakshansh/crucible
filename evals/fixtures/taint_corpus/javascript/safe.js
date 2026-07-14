function getUser(db) {
  // Constant query, no external input.
  return db.query("SELECT * FROM users LIMIT 10");
}
