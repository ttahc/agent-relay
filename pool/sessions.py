"""Durable browser sessions and stable CSRF signing material in the private journal."""
import hashlib
import json
import secrets
import time


class DurableSessions:
    def __init__(self, service, age=8 * 60 * 60, per_actor=8):
        self.service, self.age, self.per_actor = service, age, per_actor
        self.lock = service.lock
        with self.lock, service.db:
            service.db.executescript("""
                CREATE TABLE IF NOT EXISTS web_sessions(
                    digest TEXT PRIMARY KEY, actor TEXT NOT NULL, expires REAL NOT NULL,
                    credential TEXT NOT NULL, created REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS web_secrets(name TEXT PRIMARY KEY, value BLOB NOT NULL);
            """)
            service.db.execute("INSERT OR IGNORE INTO web_secrets VALUES('csrf', ?)", (secrets.token_bytes(32),))
            self.csrf_key = service.db.execute("SELECT value FROM web_secrets WHERE name='csrf'").fetchone()[0]

    @staticmethod
    def digest(value):
        return hashlib.sha256(value.encode("ascii")).hexdigest() if isinstance(value, str) and value.isascii() else ""

    def actor(self, session_id, service):
        with self.lock:
            entry = service.db.execute("SELECT actor, expires, credential FROM web_sessions WHERE digest=?",
                                       (self.digest(session_id),)).fetchone()
            if entry and entry[1] > time.time() and json.dumps(service.session_version(entry[0])) == entry[2]:
                return entry[0]
            self.end(session_id)
            return None

    def create(self, actor, previous, credential):
        session_id, now = secrets.token_urlsafe(32), time.time()
        with self.lock, self.service.db:
            db = self.service.db
            db.execute("DELETE FROM web_sessions WHERE expires<=? OR digest=?", (now, self.digest(previous)))
            own = db.execute("SELECT digest FROM web_sessions WHERE actor=? ORDER BY created, rowid",
                             (actor,)).fetchall()
            for entry in own[:max(0, len(own) - self.per_actor + 1)]:
                db.execute("DELETE FROM web_sessions WHERE digest=?", entry)
            db.execute("INSERT INTO web_sessions VALUES(?,?,?,?,?)",
                       (self.digest(session_id), actor, now + self.age, json.dumps(credential), now))
        return session_id

    def end(self, session_id):
        with self.lock, self.service.db:
            self.service.db.execute("DELETE FROM web_sessions WHERE digest=?", (self.digest(session_id),))
