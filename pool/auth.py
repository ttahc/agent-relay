"""Private password records, bounded verification, and recoverable credential changes."""
import hashlib
import hmac
import secrets
from threading import BoundedSemaphore
import time
import unicodedata

from .packages import ClientError
from 协作存储 import digest, encoded


SCRYPT = (32768, 8, 3)
MEMORY_LIMIT = 48 * 1024 * 1024
WEAK = {
    "123456789012345", "12345678901234567890", "123456789123456789", "qwertyuiopasdfghjkl",
    "passwordpassword", "iloveyouiloveyou", "1234567890qwerty", "qwerty123456789",
    "administrator123", "taskpoolpassword", "changemechangeme", "1234567890password",
    "qwertyuiop123456", "adminadminadmin", "qwertyuiopqwertyuiop", "taskpooltaskpool",
}


def normalize(value):
    if not isinstance(value, str):
        raise ClientError("密码格式无效")
    value = unicodedata.normalize("NFC", value)
    if "\0" in value:
        raise ClientError("密码格式无效")
    return value


def validate(value, account):
    value = normalize(value)
    if value == "":
        return value
    folded = value.casefold()
    repeated = any(folded == (folded[:length] * (len(folded) // length))
                   for length in range(1, min(5, len(folded) // 2 + 1)))
    if folded in WEAK or repeated or folded in {account.casefold() * i for i in range(1, 9)}:
        raise ClientError("该密码较常见或容易猜测，请换一个较长的密码短语")
    return value


class Passwords:
    def __init__(self, db, lock, accounts):
        self.db, self.lock, self.accounts = db, lock, accounts
        self.slots = BoundedSemaphore(2)
        self.dummy_salt = secrets.token_bytes(16)
        db.executescript("""
            CREATE TABLE IF NOT EXISTS person_passwords(
                name TEXT PRIMARY KEY COLLATE NOCASE, algorithm TEXT NOT NULL, salt BLOB NOT NULL,
                verifier BLOB NOT NULL, n INTEGER NOT NULL, r INTEGER NOT NULL, p INTEGER NOT NULL,
                version INTEGER NOT NULL, block_legacy INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS pending_passwords(
                key TEXT PRIMARY KEY, name TEXT NOT NULL, salt BLOB NOT NULL, verifier BLOB NOT NULL,
                kind TEXT NOT NULL, prior_version INTEGER NOT NULL, reset_sha TEXT
            );
            CREATE TABLE IF NOT EXISTS person_resets(
                name TEXT PRIMARY KEY, proof_sha TEXT NOT NULL UNIQUE, expires INTEGER NOT NULL,
                issuer TEXT NOT NULL, issue_key TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS login_attempts(
                bucket TEXT PRIMARY KEY, first INTEGER NOT NULL, count INTEGER NOT NULL, retry INTEGER NOT NULL
            );
        """)

    def get(self, name):
        return self.db.execute(
            "SELECT name,algorithm,salt,verifier,n,r,p,version,block_legacy FROM person_passwords WHERE name=?",
            (name,),
        ).fetchone()

    def version(self, name):
        row = self.get(name)
        return row[7] if row else 0

    def legacy_allowed(self, name):
        row = self.get(name)
        return not row or not row[8]

    @staticmethod
    def derive(value, salt, params=SCRYPT):
        n, r, p = params
        try:
            return hashlib.scrypt(value.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32, maxmem=MEMORY_LIMIT)
        except (AttributeError, ValueError, MemoryError) as error:
            raise ClientError("本机密码验证暂不可用", 503) from error

    def protect(self, value, name):
        value = validate(value, name)
        if not self.slots.acquire(blocking=False):
            raise ClientError("密码处理繁忙，请稍后重试", 429)
        try:
            salt = secrets.token_bytes(16)
            return salt, self.derive(value, salt)
        finally:
            self.slots.release()

    def throttle(self, name):
        now = int(time.time())
        key = digest(encoded(["login", name.casefold()[:80]]))
        with self.lock, self.db:
            self.db.execute("DELETE FROM login_attempts WHERE first<? AND retry<=?", (now - 900, now))
            for bucket, interval, maximum in (("global", 60, 120), (key, 900, 5)):
                row = self.db.execute("SELECT first,count,retry FROM login_attempts WHERE bucket=?",
                                      (bucket,)).fetchone()
                first, count, retry = row or (now, 0, 0)
                if retry > now:
                    raise ClientError("尝试过于频繁，请稍后重试", 429)
                if first + interval <= now:
                    first, count = now, 0
                count += 1
                wait = (max(1, first + interval - now) if bucket == "global" else
                        min(900, 30 * 2 ** min(5, count - maximum))) if count >= maximum else 0
                self.db.execute("INSERT OR REPLACE INTO login_attempts VALUES(?,?,?,?)",
                                (bucket, first, count, now + wait if wait else 0))
        return key

    def authenticate(self, name, value):
        if not self.slots.acquire(blocking=False):
            raise ClientError("密码处理繁忙，请稍后重试", 429)
        try:
            bucket = self.throttle(name)
            valid_input = True
            try:
                value = normalize(value)
            except ClientError:
                value = ""
                valid_input = False
            with self.lock:
                row = self.get(name)
            supported = row and row[1] == "scrypt" and row[4:7] == SCRYPT
            calculated = self.derive(value, row[2] if supported else self.dummy_salt)
            if not supported or not valid_input or not hmac.compare_digest(row[3], calculated):
                return None
            with self.lock, self.db:
                if row != self.get(name):
                    return None
                self.db.execute("DELETE FROM login_attempts WHERE bucket=?", (bucket,))
            return row[0], row[7]
        finally:
            self.slots.release()

    def stage(self, key, name, secret, kind, reset_sha=None):
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO pending_passwords VALUES(?,?,?,?,?,?,?)",
                            (key, name, *secret, kind, self.version(name), reset_sha))

    def discard(self, key):
        with self.db:
            self.db.execute("DELETE FROM pending_passwords WHERE key=?", (key,))

    def apply(self, key, kind, name):
        row = self.db.execute(
            "SELECT salt,verifier,kind,prior_version,reset_sha FROM pending_passwords WHERE key=? AND name=?",
            (key, name),
        ).fetchone()
        if not row or row[2] != kind or row[3] != self.version(name):
            raise RuntimeError("密码写入与持久请求不一致")
        salt, verifier, _, prior, reset_sha = row
        if reset_sha:
            used = self.db.execute("DELETE FROM person_resets WHERE name=? AND proof_sha=?", (name, reset_sha))
            if used.rowcount != 1:
                raise RuntimeError("重置凭据与持久请求不一致")
        else:
            self.db.execute("DELETE FROM person_resets WHERE name=?", (name,))
        block_legacy = int(kind != "setup")
        self.db.execute("INSERT OR REPLACE INTO person_passwords VALUES(?,?,?,?,?,?,?,?,?)",
                        (name, "scrypt", salt, verifier, *SCRYPT, prior + 1, block_legacy))
        self.db.execute("DELETE FROM pending_passwords WHERE key=?", (key,))

    def issue_reset(self, actor, key, name):
        code = self.accounts.token("password-reset", key, name)
        self.db.execute("INSERT OR REPLACE INTO person_resets VALUES(?,?,?,?,?)",
                        (name, digest(code.encode("ascii")), int(time.time()) + 900, actor, key))

    def reset_reply(self, key, name):
        row = self.db.execute("SELECT issue_key,expires FROM person_resets WHERE name=?", (name,)).fetchone()
        if not row or row[0] != key or row[1] <= time.time():
            raise ClientError("重置凭据已使用、替换或过期", 409)
        return self.accounts.token("password-reset", key, name)

    def check_reset(self, name, code):
        if not isinstance(code, str) or len(code) != 43 or not code.isascii():
            raise ClientError("重置凭据无效或已到期", 403)
        proof = digest(code.encode("ascii"))
        row = self.db.execute("SELECT proof_sha,expires FROM person_resets WHERE name=?", (name,)).fetchone()
        if not row or row[1] <= time.time() or not hmac.compare_digest(proof, row[0]):
            raise ClientError("重置凭据无效或已到期", 403)
        return proof
