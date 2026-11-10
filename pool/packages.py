"""Bounded transfer format for the documentation pilot."""

import base64
import binascii
from io import BytesIO
import json
import ntpath
from pathlib import PurePosixPath
import re
import zipfile

from 协作存储 import digest, encoded
from 协作取证 import output_contract


MAX_PACKAGE = 8 * 1024 * 1024
MAX_EXPANDED = 24 * 1024 * 1024
MAX_FILES = 100
MAX_JSON = 12 * 1024 * 1024
SHA = re.compile(r"[0-9a-f]{64}")


class ClientError(ValueError):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def fields(data, required):
    if not isinstance(data, dict) or set(data) != set(required.split()):
        raise ClientError("请求字段应为 " + required)


def string(value, label, limit=2000):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ClientError(f"{label} 必须为 1 至 {limit} 字符的非空文本")
    return value


def integer(value, label):
    if type(value) is not int or not 0 < value <= 10**9:
        raise ClientError(f"{label} 必须为正整数")
    return value


def strict_json(raw):
    def unique(pairs):
        result = dict(pairs)
        if len(result) != len(pairs):
            raise ValueError("JSON 包含重复字段")
        return result

    def invalid(value):
        raise ValueError(f"JSON 不支持 {value}")

    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=invalid)
        encoded(data)  # Reject isolated surrogates and non-finite numbers.
        return data
    except (ValueError, RecursionError) as error:
        raise ClientError("无效的 UTF-8 JSON") from error


def artifact_name(name):
    if not isinstance(name, str) or len(name) > 160 or "\\" in name or "\0" in name:
        raise ClientError("产物路径无效")
    for part in name.split("/"):
        if (part in {"", ".", ".."} or len(part) > 64 or part.startswith(".")
                or ntpath.isreserved(part)):
            raise ClientError("产物路径包含越界或保留名称")
    return name


def zip_bytes(files, compression=zipfile.ZIP_DEFLATED):
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w", compression=compression) as archive:
        for name, raw in sorted(files.items()):
            entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.compress_type = compression
            archive.writestr(entry, raw)
    return stream.getvalue()


def reference(path, raw):
    return {"path": path, "sha256": digest(raw)}


def unpack_delivery(body):
    sha = body["package_sha256"]
    try:
        raw = base64.b64decode(body["package"], validate=True)
    except (TypeError, ValueError, binascii.Error) as error:
        raise ClientError("交付包必须为 Base64 ZIP") from error
    if len(raw) > MAX_PACKAGE:
        raise ClientError("交付 ZIP 超出 8 MiB", 413)
    if not isinstance(sha, str) or not SHA.fullmatch(sha) or digest(raw) != sha:
        raise ClientError("交付 ZIP 的 SHA256 不符")
    try:
        with zipfile.ZipFile(BytesIO(raw)) as archive:
            entries = archive.infolist()
            if not 2 < len(entries) <= MAX_FILES or sum(e.file_size for e in entries) > MAX_EXPANDED:
                raise ClientError("交付 ZIP 超出文件数或解压大小限制")
            names = {}
            paths = {}
            for entry in entries:
                name = artifact_name(entry.orig_filename)
                if (entry.is_dir() or (entry.external_attr >> 16) & 0o170000 not in {0, 0o100000}
                        or entry.flag_bits & 1 or entry.compress_type not in {0, 8}):
                    raise ClientError("交付 ZIP 只接受未加密的普通文件")
                key = name.casefold()
                if key in names:
                    raise ClientError("交付 ZIP 包含重名文件")
                names[key] = name
                for parent in PurePosixPath(name).parents:
                    if str(parent) != ".":
                        prior = paths.setdefault(str(parent).casefold(), str(parent))
                        if prior != str(parent):
                            raise ClientError("交付 ZIP 包含大小写不同的同名目录")
            if names.keys() & paths.keys():
                raise ClientError("交付 ZIP 包含同名文件和目录")
            files = {entry.filename: archive.read(entry) for entry in entries}
        manifest = strict_json(files["manifest.json"])
        fields(manifest, "task_id claim_id revision scope_version inputs outputs")
        outputs = output_contract(manifest)
        if set(files) != {"manifest.json"} | {o["path"] for o in outputs}:
            raise ClientError("ZIP 文件与 manifest 输出清单不一致")
        for item in outputs:
            content = files[item["path"]]
            if item["bytes"] != len(content) or item["sha256"].lower() != digest(content):
                raise ClientError("交付输出长度或 SHA256 不符")
        delivery = strict_json(files["delivery.json"])
        return files, manifest, delivery
    except ClientError:
        raise
    except (ValueError, KeyError, TypeError, RuntimeError, OSError, EOFError, zipfile.BadZipFile) as error:
        raise ClientError("交付 ZIP 或清单无效") from error


def seal_metadata(claim, revision):
    return {
        "claim_id": claim["claim_id"], "revision": revision, "inputs": claim["inputs"],
        "scope_version": claim["W"]["scope"],
        "execution": dict.fromkeys(("compiled", "tested", "applied", "deployed"), False),
        "remaining": [], "claimed_resolved": [],
    }


def make_delivery(claim, artifacts):
    if not artifacts or {"manifest.json", "delivery.json"} & {n.casefold() for n in artifacts}:
        raise ClientError("须有实际产物，且文件名不能占用交付元数据")
    for name in artifacts:
        artifact_name(name)
    revision = "revision-" + str(len(claim["deliveries"]) + 1)
    delivery = seal_metadata(claim, revision)
    files = {**artifacts, "delivery.json": encoded(delivery)}
    manifest = {key: delivery[key] for key in ("claim_id", "revision", "scope_version", "inputs")}
    manifest.update(task_id=claim["task_id"], outputs=[
        {**reference(name, raw), "bytes": len(raw)} for name, raw in sorted(files.items())
    ])
    files["manifest.json"] = encoded(manifest)
    return zip_bytes(files)


def ledger_package(env, prefix, files):
    data = {"payload/" + prefix + "/" + name: raw for name, raw in files.items()}
    data["envelopes/seal.json"] = encoded(env)
    data["PACKAGE.json"] = encoded({
        "kind": "delivery", "repo_id": env["repo_id"], "origin_id": env["origin_id"],
        "claim_id": env["payload"]["claim_id"],
        "files": [{**reference(name, raw), "bytes": len(raw)} for name, raw in sorted(data.items())],
    })
    return zip_bytes(data)
