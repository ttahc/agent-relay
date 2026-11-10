#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Immutable files on a qualified local filesystem."""
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid


class Rejected(ValueError):
    def __init__(self, reason, category="format"):
        super().__init__(reason)
        self.category = category


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def check_ancestors(root):
    """Check every ancestor on every call, using one lstat per directory."""
    for ancestor in root.parents:
        try:
            info = ancestor.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 1024:
            raise ValueError("根目录祖先包含链接或重解析点")


def safe(root, relative):
    """Reject ambiguous Windows names and links instead of normalizing them away."""
    relative = str(relative)
    parts = relative.split("/")
    if not relative or any(c in relative for c in "\\:\0"):
        raise ValueError("路径必须为正斜杠相对路径")
    for part in parts:
        if (part in {"", ".", ".."} or part.rstrip(" .") != part or
                any(c in part for c in '<>"|?*') or any(ord(c) < 32 for c in part) or
                re.fullmatch(r"(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", part)):
            raise ValueError("路径包含越界、空段或Windows歧义名称")
    root = Path(root).absolute()
    check_ancestors(root)
    current = root
    for part in (None, *parts):
        if part is not None:
            current = current / part
        if current.is_symlink():
            raise ValueError("不接受链接路径")
        if current.exists() and getattr(current.lstat(), "st_file_attributes", 0) & 1024:
            raise ValueError("不接受重解析路径")
    current.resolve().relative_to(root.resolve())
    return current


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def publish(path, data, checkpoint=None):
    """Flush a private sibling, then publish once without replacing an existing name.

    Readers never inspect .pending files. Process interruption can leave a staging
    file; it cannot expose a partially written target. No recovery/deletion of
    another writer's files is attempted.
    """
    path = Path(path)
    missing = []
    if os.name == "posix":
        directory = path.parent
        while not directory.exists():
            missing.append(directory)
            directory = directory.parent
    path.parent.mkdir(parents=True, exist_ok=True)
    for directory in reversed(missing):
        sync_directory(directory.parent)
    pending = path.parent / (".pending-" + uuid.uuid4().hex)
    try:
        with pending.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if checkpoint:
            checkpoint("staged")
        try:
            if os.name == "nt":
                os.rename(pending, path)  # Windows rename refuses an existing destination.
            else:
                os.link(pending, path)  # Atomic no-replace publication on local ext4.
        except FileExistsError:
            if os.name == "posix":
                sync_directory(path.parent)
            return False
        except PermissionError:
            if path.exists():
                return False
            raise
        if os.name == "posix":
            sync_directory(path.parent)
        if checkpoint:
            checkpoint("published")
        return True
    finally:
        try:
            pending.unlink(missing_ok=True)
        except OSError:
            pass  # Own staging only; publication and permission evidence are preserved.


def ntfs_identity(path):
    """Bind qualification to this machine, fixed volume, and exact store location."""
    if os.name != "nt":
        raise ValueError("未验证的操作系统只能投递信封")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    volume = ctypes.create_unicode_buffer(32768)
    get_path = kernel.GetVolumePathNameW
    get_path.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    get_path.restype = wintypes.BOOL
    path = Path(path).absolute()
    if not get_path(str(path), volume, len(volume)):
        raise ctypes.WinError(ctypes.get_last_error())
    drive_type = kernel.GetDriveTypeW
    drive_type.argtypes = [wintypes.LPCWSTR]
    drive_type.restype = wintypes.UINT
    serial = wintypes.DWORD()
    fs_name = ctypes.create_unicode_buffer(64)
    get_info = kernel.GetVolumeInformationW
    get_info.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD,
                         ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
                         ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR, wintypes.DWORD]
    get_info.restype = wintypes.BOOL
    if not get_info(volume, None, 0, ctypes.byref(serial), None, None, fs_name, len(fs_name)):
        raise ctypes.WinError(ctypes.get_last_error())
    if drive_type(volume) != 3 or fs_name.value != "NTFS":
        raise ValueError("远程挂载或非NTFS环境只能投递信封")
    return {"machine": os.environ.get("COMPUTERNAME", ""), "volume": volume.value.casefold(),
            "serial": serial.value, "filesystem": fs_name.value, "store": str(path).casefold()}
