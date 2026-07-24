import http.server
import os
import pickle
import subprocess


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # DSVW-style: tuple unpack from self.path, a params dict, then sinks.
        path, query = self.path.split("?", 1) if "?" in self.path else (self.path, "")
        params = dict(p.split("=") for p in query.split("&") if "=" in p)
        cursor = db.cursor()
        if path == "/user":
            cursor.execute("SELECT * FROM users WHERE id=" + params["id"])  # SQLi (13)
        elif path == "/file":
            content = open(params["path"]).read()  # path traversal (15)
        elif path == "/run":
            subprocess.run("ping " + params["host"], shell=True)  # cmd injection (17)
        elif path == "/load":
            obj = pickle.loads(params["blob"].encode())  # deserialization (19)

    def do_POST(self):
        # A safe endpoint: parameterized query.
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        params = dict(p.split("=") for p in body.split("&") if "=" in p)
        db.cursor().execute("INSERT INTO t VALUES (?)", (params["x"],))  # safe: parameterized


class NotAHandler:
    """self.path here is a filesystem attribute, NOT request input."""

    def load(self):
        return open(self.path).read()  # must NOT be flagged (not a handler)
