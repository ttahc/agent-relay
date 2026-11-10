"""Freeze private Podman launch inputs and replay them without shell reconstruction."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys


def launch_arguments(record, image, name, archive, tag, config_sha=None):
    config, host = record["config"], record["host"]
    args = ["podman", "run", "-d", "--pull=never", "--name", name]
    for value in config.get("Env", []):
        if not isinstance(value, str) or "=" not in value or "\0" in value:
            raise ValueError("启动环境配置无效")
        if not value.startswith("TASKPOOL_LAUNCH_CONFIG_SHA256="):
            args += ["--env", value]
    if config_sha:
        args += ["--env", "TASKPOOL_LAUNCH_CONFIG_SHA256=" + config_sha]
    for key, value in {**config.get("Labels", {}), "upgrade": tag}.items():
        args += ["--label", key + "=" + value]
    for field, flag in (("User", "--user"), ("WorkingDir", "--workdir"), ("Hostname", "--hostname"), ("StopSignal", "--stop-signal")):
        if config.get(field):
            args += [flag, str(config[field])]
    if config.get("Entrypoint"):
        args += ["--entrypoint", json.dumps(config["Entrypoint"], separators=(",", ":"))]
    if host.get("ReadonlyRootfs"):
        args.append("--read-only")
    for value in host.get("CapDrop", []):
        args += ["--cap-drop", value]
    for value in host.get("CapAdd", []):
        args += ["--cap-add", value]
    for value in host.get("SecurityOpt", []):
        args += ["--security-opt", value]
    if host.get("Privileged"):
        raise ValueError("升级工具不重建特权容器，请先核对专用启动配置")
    if host.get("PidsLimit") not in (None, 0):
        args += ["--pids-limit", str(host["PidsLimit"])]
    for field, flag in (("Memory", "--memory"), ("MemorySwap", "--memory-swap"), ("CpuQuota", "--cpu-quota"),
                        ("CpuPeriod", "--cpu-period"), ("CpusetCpus", "--cpuset-cpus"), ("ShmSize", "--shm-size"),
                        ("UsernsMode", "--userns")):
        if host.get(field):
            args += [flag, str(host[field])]
    for group in host.get("GroupAdd", []) or []:
        args += ["--group-add", str(group)]
    for limit in host.get("Ulimits", []) or []:
        args += ["--ulimit", limit["Name"] + "=" + str(limit["Soft"]) + ":" + str(limit["Hard"])]
    policy = host.get("RestartPolicy") or {}
    if policy.get("Name"):
        restart = policy["Name"]
        if restart == "on-failure" and policy.get("MaximumRetryCount"):
            restart += ":" + str(policy["MaximumRetryCount"])
        args += ["--restart", restart]
    mode = host.get("NetworkMode")
    if mode and mode not in {"default", "bridge"}:
        if mode.startswith("container:"):
            raise ValueError("不能自动重建依附另一容器的网络配置")
        args += ["--network", mode]
    for port, bindings in (host.get("PortBindings") or {}).items():
        number, _, protocol = port.partition("/")
        if not number.isdigit() or protocol not in {"tcp", "udp", "sctp"}:
            raise ValueError("端口映射配置无效")
        for binding in bindings or []:
            address = binding.get("HostIp") or "0.0.0.0"
            if ":" in address:
                address = "[" + address + "]"
            host_port = binding.get("HostPort", "")
            if not host_port.isdigit():
                raise ValueError("端口映射须已固定，不能升级时重新选择随机端口")
            args += ["--publish", address + ":" + host_port + ":" + number + "/" + protocol]
    backup_bound = False
    for mount in record["mounts"]:
        if mount["Type"] == "tmpfs":
            continue
        if mount["Type"] not in {"bind", "volume"}:
            raise ValueError("启动卷类型尚未支持，请核对后再停服")
        source = mount.get("Name") if mount["Type"] == "volume" else mount.get("Source")
        target = mount["Destination"]
        if target == "/backup":
            if mount["Type"] != "bind" or os.path.realpath(source) != os.path.realpath(archive):
                raise ValueError("原备份挂载与本次私有根不同，未自动切换")
            backup_bound = True
        if not source or any(char in source + target for char in ("\0", ":")):
            raise ValueError("启动卷路径无效，未重拼歧义路径")
        options = [value for value in mount.get("Options", []) if value not in {"rw", "ro"}]
        options.insert(0, "rw" if mount.get("RW") else "ro")
        args += ["--volume", source + ":" + target + ":" + ",".join(options)]
    if not backup_bound:
        args += ["--volume", archive + ":/backup:rw"]
    for target, options in (host.get("Tmpfs") or {}).items():
        args += ["--tmpfs", target + ":" + options]
    args += [image, *config["Cmd"]]
    return args


def freeze(record, output, image, name, archive, tag):
    if isinstance(record, list):
        if len(record) != 1:
            raise ValueError("须指定唯一原服务容器")
        record = record[0]
    config = record.get("Config", {})
    if not isinstance(config.get("Cmd"), list) or not all(isinstance(item, str) for item in config["Cmd"]):
        raise ValueError("原服务启动参数无效")
    if "serve" not in config["Cmd"]:
        raise ValueError("原容器不是已核对的 serve 启动入口")
    value = {"format": 1, "prior_image": record.get("Image"), "config": config,
             "host": record.get("HostConfig", {}), "mounts": record.get("Mounts", [])}
    launch_arguments(value, image, name, archive, tag)  # Validate before any stop.
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True).encode()
    with output.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("freeze", "launch"))
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--tag", required=True)
    args = parser.parse_args()
    if os.name == "posix":
        os.umask(0o077)
    if args.mode == "freeze":
        print(freeze(json.load(sys.stdin), args.config, args.image, args.name, args.archive, args.tag))
    else:
        if str(args.config) == "-":
            raw = sys.stdin.buffer.read(4 * 1024 * 1024 + 1)
        else:
            if args.config.is_symlink() or os.name == "posix" and args.config.stat().st_mode & 0o077:
                raise ValueError("启动配置须为私有普通文件")
            raw = args.config.read_bytes()
        if len(raw) > 4 * 1024 * 1024:
            raise ValueError("启动配置超出预算")
        record = json.loads(raw)
        os.execvp("podman", launch_arguments(record, args.image, args.name, args.archive, args.tag, hashlib.sha256(raw).hexdigest()))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError):
        print("启动配置核对或重建失败；私有配置和原数据保留，请检查受限诊断。", file=sys.stderr)
        sys.exit(1)
