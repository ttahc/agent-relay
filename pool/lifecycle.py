"""Bounded graceful maintenance, separate from business task state."""
from contextlib import contextmanager
import hmac
import json
import os
from pathlib import Path
import secrets
import socket
import threading
import time


class Maintenance(RuntimeError):
    retry_after = 3


class Lifecycle:
    def __init__(self):
        self.condition = threading.Condition(threading.RLock())
        self.local = threading.local()
        self.phase = "running"
        self.active = 0
        self.changed = time.time()
        self.reason = ""
        self.listeners = []  # called on every phase change, with the condition held: they must not block

    def _set(self, phase, reason=""):
        self.phase, self.reason, self.changed = phase, reason, time.time()
        self.condition.notify_all()
        for listener in self.listeners:
            listener()

    def status(self):
        with self.condition:
            return {"phase": self.phase, "active_requests": self.active, "changed_at": self.changed,
                    "reason": self.reason, "retry_after": Maintenance.retry_after,
                    "business_execution": "unchanged"}

    def drain(self):
        with self.condition:
            if self.phase == "running":
                self._set("draining", "暂停新领取和新的自动开工；已有任务继续执行")
            return self.status()

    def cancel(self):
        with self.condition:
            if self.phase == "backing_up":
                raise ValueError("一致性备份正在完成，请等待；不能在复制中途恢复业务写入")
            self._set("running", "升级已取消，继续接收请求")
            return self.status()

    def freeze(self, timeout=30):
        if not isinstance(timeout, (int, float)) or not 0 < timeout <= 120:
            raise ValueError("排空时限须大于 0 且不超过 120 秒")
        deadline = time.monotonic() + timeout
        with self.condition:
            if self.phase == "backing_up":
                raise ValueError("一致性备份正在完成，暂不开始另一次停写")
            # Stop admitting reads too: session expiry and read-side caches can write.
            self._set("freezing", "等待已接收请求完成；任务执行继续")
            while self.active:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._set("running", "排空超时，已取消升级；没有强制终止请求")
                    return self.status()
                self.condition.wait(remaining)
                if self.phase != "freezing":
                    return self.status()
            self._set("frozen", "请求已排空，可安全停止写实例")
            return self.status()

    @contextmanager
    def backup_window(self, timeout=30):
        with self.condition:
            previous = self.phase
            if previous not in {"running", "draining"}:
                raise ValueError("服务正在切换或备份，不能开始另一份备份")
        if self.freeze(timeout)["phase"] != "frozen":
            with self.condition:
                self._set(previous, "备份排空未完成，已恢复原接入状态")
            raise ValueError("备份排空超时，已取消本次备份")
        with self.condition:
            if self.phase != "frozen":
                raise ValueError("备份窗口已被取消，请重试")
            self._set("backing_up", "正在生成一致性私有备份；任务执行继续")
        try:
            yield
        finally:
            with self.condition:
                self._set(previous, "备份窗口已结束，恢复原接入状态")

    def check_new_work(self, action, body=None):
        with self.condition:
            # An admitted request may finish even if freeze began while reading it.
            if self.phase in {"freezing", "frozen", "backing_up"} and not getattr(self.local, "admitted", False):
                raise Maintenance("服务正在升级，请保留原请求并稍后重试")
            new_work = (action in {"claim", "resume", "segment-open", "action-start"}
                        or (action == "run-report" and (body or {}).get("state") == "intent"))
            if self.phase != "running" and new_work:
                raise Maintenance("升级排空中，暂缓新领取或新开工；原任务与占用保留")

    @contextmanager
    def admit(self, method, path):
        with self.condition:
            if self.phase in {"freezing", "frozen", "backing_up"}:
                raise Maintenance("服务正在升级，请保留原请求并稍后重试")
            self.check_new_work(path.removeprefix("/v1/") if method == "POST" else "")
            self.active += 1
            self.local.admitted = True
        try:
            yield
        finally:
            with self.condition:
                self.local.admitted = False
                self.active -= 1
                self.condition.notify_all()


class Control:
    """Private Unix-domain control endpoint; never exposed by the HTTP listener."""

    def __init__(self, store, lifecycle, shutdown, backup=None):
        if os.name != "posix":
            raise ValueError("升级管理接口须在 Linux/WSL 服务内使用")
        self.path = Path(store) / "upgrade-control.sock"
        self.key_path = Path(store) / "upgrade-control.key"
        if len(os.fsencode(self.path)) > 100:
            raise ValueError("升级控制 socket 路径过长，请使用服务内的短数据卷路径")
        self.lifecycle, self.shutdown = lifecycle, shutdown
        self.backup = backup
        self.token = secrets.token_hex(32)
        # Caller already owns the exclusive writer lock; stale socket is safe to replace.
        self.path.unlink(missing_ok=True)
        self.key_path.unlink(missing_ok=True)
        fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            stream.write(self.token)
            stream.flush()
            os.fsync(stream.fileno())
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.bind(str(self.path))
        os.chmod(self.path, 0o600)
        self.socket.listen(4)
        self.socket.settimeout(0.25)
        self.stopped = threading.Event()
        self.slots = threading.BoundedSemaphore(8)
        self.thread = threading.Thread(target=self._serve, name="upgrade-control", daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stopped.set()
        self.thread.join(2)
        self.socket.close()
        self.path.unlink(missing_ok=True)
        self.key_path.unlink(missing_ok=True)

    def _serve(self):
        while not self.stopped.is_set():
            try:
                connection, _ = self.socket.accept()
            except socket.timeout:
                continue
            if not self.slots.acquire(blocking=False):
                connection.close()
                continue
            threading.Thread(target=self._handle, args=(connection,), daemon=True).start()

    def _handle(self, connection):
        try:
            with connection:
                connection.settimeout(2)
                try:
                    with connection.makefile("rb") as stream:
                        raw = stream.readline(4097)
                    if len(raw) > 4096 or not raw.endswith(b"\n"):
                        raise ValueError("控制请求过大或未完整到达")
                    value = json.loads(raw)
                    if not isinstance(value, dict) or not hmac.compare_digest(str(value.get("token", "")), self.token):
                        raise ValueError("本机升级控制认证失败")
                    command = value.get("command")
                    if command == "status":
                        result = self.lifecycle.status()
                    elif command == "drain":
                        result = self.lifecycle.drain()
                    elif command == "cancel":
                        result = self.lifecycle.cancel()
                    elif command == "backup":
                        if self.backup is None:
                            raise ValueError("当前服务未配置一致性备份")
                        result = self.backup(value.get("archive"), value.get("tag"), value.get("timeout", 30))
                    elif command in {"freeze", "shutdown"}:
                        result = self.lifecycle.freeze(value.get("timeout", 30))
                        if command == "shutdown" and result["phase"] == "frozen":
                            threading.Thread(target=self.shutdown, daemon=True).start()
                    else:
                        raise ValueError("未知升级控制命令")
                    response = {"ok": True, **result}
                except (ValueError, OSError, TypeError) as error:
                    response = {"ok": False, "message": str(error)}
                except Exception as error:
                    from .privacy import log_exception
                    incident = log_exception(error)
                    response = {"ok": False, "message": "本机控制未完成，请检查诊断编号 " + incident}
                try:
                    connection.sendall(json.dumps(response, ensure_ascii=False).encode("utf-8") + b"\n")
                except OSError:
                    pass
        finally:
            self.slots.release()


def control_request(store, command, timeout=30, *, archive=None, tag=None):
    if os.name != "posix":
        raise ValueError("升级管理接口须在 Linux/WSL 服务内使用")
    store = Path(store)
    key = store / "upgrade-control.key"
    if key.is_symlink() or key.stat().st_mode & 0o077 or key.stat().st_uid != os.getuid():
        raise ValueError("升级控制凭据须为当前服务用户的私有文件")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout + (300 if command == "backup" else 5))
        connection.connect(str(store / "upgrade-control.sock"))
        connection.sendall(json.dumps({"token": key.read_text(encoding="ascii"), "command": command,
                                       "timeout": timeout, "archive": archive, "tag": tag}).encode("utf-8") + b"\n")
        with connection.makefile("rb") as stream:
            result = json.loads(stream.readline(8192))
    if not result.get("ok"):
        raise ValueError(result.get("message", "升级控制失败"))
    return result
