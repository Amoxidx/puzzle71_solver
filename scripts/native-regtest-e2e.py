#!/usr/bin/env python3
"""Run the real native wallet UI against a disposable Bitcoin Core regtest.

Requires macOS, Xcode/Swift, Docker (locally or through --docker-ssh-host), and a
caller-built rehearsal binary. No Cargo build, production endpoint, JavaScript
mock, wallet dump, key-file read, or raw-transaction log is used.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "bitcoin/bitcoin:30.0"
FUNDING_SAT = 800_000_000
AUTH = "Basic " + base64.b64encode(b"p71:p71regtest").decode()
PROTECTED_PORTS = {8080, 18443, 60401}


class Failure(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise Failure(message)


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    path = Path(path)
    require(not path.name.startswith(("FOUND_KEY", ".FOUND_KEY")), "Refuse key-file read")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def atomic_json(path, value):
    temporary = path.with_name("." + path.name + "." + uuid.uuid4().hex)
    with temporary.open("x", encoding="utf-8") as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def bounded_json(path, limit=1_048_576):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        meta = os.fstat(stream.fileno())
        require(stat.S_ISREG(meta.st_mode) and meta.st_uid == os.getuid() and meta.st_nlink == 1,
                "Unsafe JSON file owner or type")
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, "JSON file exceeds bound")
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "Duplicate JSON field")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(Failure("Nonfinite JSON")))


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    require(port not in PROTECTED_PORTS, "Reserved port selected")
    return port


def port_free(port):
    with socket.socket() as sock:
        return sock.connect_ex(("127.0.0.1", port)) != 0


def owned_listener(port, pid):
    probe = subprocess.run(["lsof", "-nP", f"-ti4TCP:{port}", "-sTCP:LISTEN"],
                           stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=5)
    require(probe.returncode in (0, 1) and not probe.stderr.strip(), "Cannot identify owned loopback listener")
    observed = {int(value) for value in probe.stdout.split()}
    require(not observed or observed == {pid}, "Loopback listener belongs to another process")
    return observed == {pid}


def satoshis(value):
    amount = Decimal(str(value)) * Decimal(100_000_000)
    require(amount.is_finite() and amount == amount.to_integral_value() and amount >= 0,
            "Core returned a nonintegral satoshi value")
    return int(amount)


def native_case_counts(expected, result):
    require(isinstance(result, dict) and result.get("schema") == 1 and isinstance(result.get("cases"), list),
            "Unknown native partial-result schema")
    cases = result["cases"]
    require(all(isinstance(case, dict) and type(case.get("passed")) is bool for case in cases),
            "Invalid native case result")
    require([case.get("id") for case in cases] == expected[:len(cases)] and len(cases) <= len(expected),
            "Native partial cases are duplicated, reordered or unknown")
    passed = sum(case["passed"] is True for case in cases)
    return {"expected": len(expected), "executed": len(cases), "passed": passed,
            "failed": len(cases) - passed, "not_executed": len(expected) - len(cases)}


class Child:
    """Only direct, unreaped Popen children and their isolated groups are signalled."""
    def __init__(self, argv, cwd, environment, private, label, public_logs=None):
        self.argv, self.label = [str(x) for x in argv], label
        self.started = now()
        self.paths = [private / (label + ".stdout"), private / (label + ".stderr")]
        self.public_logs = public_logs if label in {"compile-swift", "list-cases", "native-driver"} else None
        self.finished = False
        self.streams = [p.open("xb") for p in self.paths]
        try:
            self.process = subprocess.Popen(self.argv, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                                            stdout=self.streams[0], stderr=self.streams[1], start_new_session=True)
        except BaseException:
            for stream in self.streams:
                stream.close()
            raise
        self.record = {"argv": self.argv, "cwd": str(cwd), "pid": self.process.pid,
                       "started_at": self.started, "label": label}

    def stop(self):
        if self.process.poll() is None:
            require(os.getpgid(self.process.pid) == self.process.pid, "Owned child group changed")
            os.killpg(self.process.pid, signal.SIGTERM)
            self.record["sigterm_own_group"] = True
            try:
                self.process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                require(os.getpgid(self.process.pid) == self.process.pid, "Owned child group changed")
                os.killpg(self.process.pid, signal.SIGKILL)
                self.record["sigkill_own_group_after_timeout"] = True
                self.process.wait(timeout=10)
        return self.finish()

    def finish(self):
        if self.finished:
            return self.record
        require(self.process.poll() is not None, "Owned child still running")
        for stream in self.streams:
            stream.close()
        self.record.update(finished_at=now(), exit_code=self.process.returncode)
        self.record["private_output_hashes"] = {
            p.suffix[1:]: {"bytes": p.stat().st_size, "sha256": digest(p)} for p in self.paths}
        if self.public_logs:
            self.record["retained_safe_output"] = {}
            for path in self.paths:
                destination = self.public_logs / (path.name + ".log")
                with destination.open("xb") as stream:
                    os.fchmod(stream.fileno(), 0o600)
                    stream.write(path.read_bytes())
                    stream.flush()
                    os.fsync(stream.fileno())
                self.record["retained_safe_output"][path.suffix[1:]] = {
                    "path": str(destination), "bytes": destination.stat().st_size, "sha256": digest(destination)}
        else:
            self.record["output_retention"] = "Private hash-only capture; not published and removed with owned sensitive tempdir after cleanup"
        self.finished = True
        return self.record


class Rpc:
    def __init__(self, port):
        require(port not in PROTECTED_PORTS, "Refuse reserved RPC port")
        self.port = port

    def call(self, method, params=None, wallet=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=25)
        body = json.dumps({"jsonrpc": "1.0", "id": "native-regtest", "method": method,
                           "params": [] if params is None else params}).encode()
        try:
            connection.request("POST", "/" if wallet is None else "/wallet/" + wallet, body,
                               {"Authorization": AUTH, "Content-Type": "application/json"})
            response = connection.getresponse()
            raw = response.read(4_194_305)
            require(len(raw) <= 4_194_304, "Core RPC response exceeds bound")
            value = json.loads(raw, parse_float=Decimal)
            if value.get("error") is not None:
                raise Failure("Core RPC " + method + " returned error code " + str(value["error"].get("code")))
            require(response.status == 200, "Core RPC HTTP failure")
            return value["result"]
        finally:
            connection.close()


class FaultProxy:
    """Real RPC passthrough; only an accepted submit ACK or status transport is dropped."""
    def __init__(self, rpc):
        self.rpc, self.lock = rpc, threading.Lock()
        self.drop_next, self.outage = False, False
        self.counts = {"send_attempts": 0, "forwarded_submits": 0, "accepted_submits": 0,
                       "dropped_submit_replies": 0, "blocked_status_requests": 0}
        self.last_txid, self.active = None, 0
        proxy = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):
                self.connection.settimeout(20)
                connection = None
                with proxy.lock:
                    proxy.active += 1
                try:
                    require(self.path == "/" and self.headers.get("Authorization") == AUTH,
                            "Proxy request path or authentication rejected")
                    length = int(self.headers.get("Content-Length", "0"))
                    require(0 < length <= 1_048_576, "Proxy request size rejected")
                    body = self.rfile.read(length)
                    require(len(body) == length, "Proxy request incomplete")
                    request = json.loads(body)
                    method, params = request.get("method"), request.get("params", [])
                    require(method in {"getblockchaininfo", "scantxoutset", "getrawtransaction",
                                       "getblockheader", "sendrawtransaction"}, "Proxy RPC method rejected")
                    status_request = method == "getblockheader" or (
                        method == "getrawtransaction" and len(params) > 1 and params[1] is True)
                    with proxy.lock:
                        if method == "sendrawtransaction":
                            proxy.counts["send_attempts"] += 1
                        if proxy.outage and status_request:
                            proxy.counts["blocked_status_requests"] += 1
                            self.close_connection = True
                            return
                        if method == "sendrawtransaction":
                            proxy.counts["forwarded_submits"] += 1
                    connection = http.client.HTTPConnection("127.0.0.1", rpc.port, timeout=25)
                    connection.request("POST", "/", body, {"Authorization": AUTH, "Content-Type": "application/json"})
                    response = connection.getresponse()
                    raw = response.read(4_194_305)
                    require(len(raw) <= 4_194_304, "Proxy response exceeds bound")
                    value = json.loads(raw)
                    if method == "sendrawtransaction" and response.status == 200 and value.get("error") is None:
                        txid = value.get("result")
                        require(isinstance(txid, str) and re.fullmatch(r"[0-9a-f]{64}", txid), "Invalid submit receipt")
                        with proxy.lock:
                            proxy.counts["accepted_submits"] += 1
                            proxy.last_txid = txid
                            drop = proxy.drop_next
                            if drop:
                                proxy.drop_next = False
                                proxy.counts["dropped_submit_replies"] += 1
                        if drop:
                            self.close_connection = True
                            return
                    self.send_response(response.status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(raw)
                    self.close_connection = True
                except Exception:
                    # Never print request/response bodies or exception representations.
                    self.close_connection = True
                finally:
                    if connection is not None:
                        connection.close()
                    with proxy.lock:
                        proxy.active -= 1

        class Server(ThreadingHTTPServer):
            daemon_threads = True

            def handle_error(self, *_args):
                pass

        self.server = Server(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        require(self.port not in PROTECTED_PORTS, "Reserved proxy port")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def snapshot(self):
        with self.lock:
            return {**self.counts, "last_submitted_txid": self.last_txid, "status_outage": self.outage}

    def close(self):
        if self.thread.is_alive():
            self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            with self.lock:
                if self.active == 0:
                    return
            time.sleep(0.05)
        raise Failure("Own RPC proxy handlers did not drain")


class Supervisor:
    def __init__(self, args):
        self.args = args
        self.output = args.output.expanduser().resolve()
        self.output.mkdir(mode=0o700)
        self.private = Path(tempfile.mkdtemp(prefix="p71-native-regtest-"))
        self.private_identity = (self.private.stat().st_dev, self.private.stat().st_ino)
        self.backend_dir, self.control = self.private / "backend", self.private / "control"
        for path in [self.backend_dir, self.control, self.output / "build", self.output / "screenshots", self.output / "logs"]:
            path.mkdir(mode=0o700)
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(("GIT_", "PUZZLE71_", "REHEARSAL_"))
                    and k not in {"RUST_LOG", "RUST_BACKTRACE"}}
        self.token = uuid.uuid4().hex
        self.name = "p71-native-regtest-" + self.token
        self.container_id = None
        self.node_create_attempted = False
        self.children, self.backend, self.tunnel, self.native, self.proxy = [], None, None, None, None
        self.recorded_children = set()
        self.backend_port = free_port()
        self.rpc = None
        self.wallet = "native_funder_" + self.token
        self.report = {"schema": 1, "started_at": now(), "passed": False, "run_id": self.token,
                       "mode": "keystone" if args.keystone_only else "full", "own_container_name": self.name,
                       "commands": [], "actions": [], "scope": "Actual native WKWebView -> rehearsal ClaimService -> owned Core30 regtest; no production control or API/JavaScript mock"}

    def persist(self):
        atomic_json(self.output / "evidence.json", self.report)

    def record_child(self, child):
        if id(child) not in self.recorded_children:
            self.report["commands"].append(child.finish())
            self.recorded_children.add(id(child))

    def command(self, label, argv, timeout=60):
        child = Child(argv, ROOT, self.env, self.private, label, self.output / "logs")
        self.children.append(child)
        try:
            child.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            child.stop()
            raise Failure(label + " timed out")
        finally:
            if child.process.poll() is not None:
                self.record_child(child)
                self.persist()
        require(child.process.returncode == 0, label + " failed; private output is hashed, never copied")
        return child.paths[0].read_text()

    def docker_argv(self, arguments):
        command = ["docker", *arguments]
        if self.args.docker_ssh_host:
            command = ["env", "PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", *command]
            return ["ssh", "-T", "-o", "BatchMode=yes", "-o", "ControlMaster=no", "-o", "ControlPath=none",
                    "--", self.args.docker_ssh_host, shlex.join(command)]
        return command

    def inspect_owned(self):
        rows = json.loads(self.command("inspect-" + uuid.uuid4().hex[:8], self.docker_argv(["inspect", self.container_id])))
        require(len(rows) == 1, "Owned container inspection ambiguous")
        row = rows[0]
        require(row["Id"] == self.container_id and row["Name"] == "/" + self.name and
                row["Config"]["Labels"].get("p71.native-regtest-run") == self.token, "Container ownership differs")
        return row

    def setup_node(self):
        self.node_create_attempted = True
        raw = self.command("node-create", self.docker_argv([
            "run", "-d", "--rm", "--name", self.name, "--label", "p71.native-regtest-run=" + self.token,
            "--cpus", "1", "--memory", "512m", "--memory-swap", "512m", "--pids-limit", "128",
            "--publish", "127.0.0.1::18443", "--entrypoint", "bitcoind", IMAGE,
            "-regtest", "-server", "-txindex=1", "-dbcache=64", "-maxmempool=16", "-fallbackfee=0.0002",
            "-listen=0", "-discover=0", "-dnsseed=0", "-connect=0", "-rpcbind=0.0.0.0",
            "-rpcallowip=0.0.0.0/0", "-rpcuser=p71", "-rpcpassword=p71regtest", "-printtoconsole"]), timeout=180).strip()
        require(re.fullmatch(r"[0-9a-f]{64}", raw), "Docker did not return one container ID")
        self.container_id = raw
        row = self.inspect_owned()
        bindings = row["NetworkSettings"]["Ports"]["18443/tcp"]
        require(len(bindings) == 1 and bindings[0]["HostIp"] == "127.0.0.1", "Core RPC publication is not loopback-only")
        remote_port = int(bindings[0]["HostPort"])
        require(remote_port not in PROTECTED_PORTS, "Docker selected a reserved host port")
        require(row["HostConfig"]["NanoCpus"] == 1_000_000_000 and row["HostConfig"]["Memory"] == 512 * 1024 * 1024,
                "Core resource limits differ")
        require(row["HostConfig"]["AutoRemove"] is True and not row["HostConfig"].get("Binds"),
                "Core must use disposable storage without host binds")
        self.report["container"] = {"id": self.container_id, "name": self.name, "label": self.token,
            "image": IMAGE, "image_id": row["Image"], "host_rpc_port": remote_port, "host_ip": "127.0.0.1",
            "configured_cpus": 1, "configured_memory_bytes": 512 * 1024 * 1024}
        local_port = remote_port
        if self.args.docker_ssh_host:
            local_port = free_port()
            argv = ["ssh", "-T", "-o", "BatchMode=yes", "-o", "ControlMaster=no", "-o", "ControlPath=none",
                    "-o", "ExitOnForwardFailure=yes", "-N", "-L",
                    f"127.0.0.1:{local_port}:127.0.0.1:{remote_port}", "--", self.args.docker_ssh_host]
            self.tunnel = Child(argv, ROOT, self.env, self.private, "rpc-tunnel")
            self.children.append(self.tunnel)
        self.rpc = Rpc(local_port)
        deadline = time.monotonic() + 120
        while True:
            if self.tunnel:
                require(self.tunnel.process.poll() is None, "Own RPC tunnel exited")
                if not owned_listener(local_port, self.tunnel.process.pid):
                    require(time.monotonic() < deadline, "Own RPC tunnel never bound")
                    time.sleep(0.05)
                    continue
            try:
                chain = self.rpc.call("getblockchaininfo")
                break
            except (OSError, Failure, ValueError):
                require(time.monotonic() < deadline, "Fresh Core RPC did not become ready")
                time.sleep(0.2)
        require(chain["chain"] == "regtest" and chain["blocks"] == 0 and not self.rpc.call("getrawmempool"),
                "Owned node must start at fresh regtest genesis")
        network = self.rpc.call("getnetworkinfo")
        require(network["version"] == 300000, "Expected Bitcoin Core30.0")
        self.report["node"] = {"chain": "regtest", "initial_blocks": 0, "version": network["version"],
                               "subversion": network["subversion"], "local_rpc_port": local_port}

    def backend_status(self):
        if self.backend is None or self.backend.process.poll() is not None:
            return None
        if not owned_listener(self.backend_port, self.backend.process.pid):
            return None
        connection = http.client.HTTPConnection("127.0.0.1", self.backend_port, timeout=3)
        try:
            connection.request("GET", "/api/status")
            response = connection.getresponse()
            raw = response.read(262145)
            require(response.status == 200 and len(raw) <= 262144, "Invalid own backend status")
            return json.loads(raw)
        finally:
            connection.close()

    def start_backend(self):
        require(self.backend is None or self.backend.process.poll() is not None, "Own backend is already running")
        require(port_free(self.backend_port), "Own backend port is occupied")
        argv = [str(self.args.rehearsal_bin), "serve-regtest", "--dir", str(self.backend_dir),
                "--rpc", f"127.0.0.1:{self.proxy.port}", "--port", str(self.backend_port)]
        self.backend = Child(argv, self.backend_dir, dict(self.env, REHEARSAL_FEE_FLOOR="2000"),
                             self.private, "backend-" + uuid.uuid4().hex[:8])
        self.children.append(self.backend)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            require(self.backend.process.poll() is None, "Own rehearsal exited during startup")
            try:
                value = self.backend_status()
                if value and value.get("hit") and value.get("claim") is not None:
                    require(value.get("last_error") is None, "Own rehearsal startup error")
                    return {"backend_running": True, "backend_status": value}
            except (OSError, ValueError):
                pass
            time.sleep(0.05)
        raise Failure("Own rehearsal did not become ready")

    def stop_backend(self):
        if self.backend:
            self.backend.stop()
            self.record_child(self.backend)
            self.backend = None
        require(port_free(self.backend_port), "Owned rehearsal port did not become free")
        return {"backend_running": False}

    def snapshot(self):
        return {**self.proxy.snapshot(), "mempool_txids": self.rpc.call("getrawmempool"),
                "backend_status": self.backend_status(),
                "backend_running": self.backend is not None and self.backend.process.poll() is None}

    def verify_transaction(self, txid, destination, expected_output_sat):
        require(re.fullmatch(r"[0-9a-f]{64}", txid or "") and destination in self.destinations,
                "Unrecognized transaction or destination")
        require(txid == self.proxy.snapshot()["last_submitted_txid"], "Transaction was not accepted through this run's proxy")
        require(type(expected_output_sat) is int and 0 < expected_output_sat < FUNDING_SAT, "Invalid expected payout")
        tx = self.rpc.call("getrawtransaction", [txid, True])
        require(tx["txid"] == txid and len(tx["vout"]) == 1, "Node transaction ID/output count differs")
        inputs = []
        for item in tx["vin"]:
            previous = self.rpc.call("getrawtransaction", [item["txid"], True])
            amount = satoshis(previous["vout"][item["vout"]]["value"])
            inputs.append({"txid": item["txid"], "vout": item["vout"], "value_sat": amount})
        outputs = [{"destination": item["scriptPubKey"].get("address"), "value_sat": satoshis(item["value"])} for item in tx["vout"]]
        total_input, total_output = sum(i["value_sat"] for i in inputs), sum(o["value_sat"] for o in outputs)
        require(total_input == FUNDING_SAT and outputs == [{"destination": destination, "value_sat": expected_output_sat}],
                "Actual Core inputs or destination/payout differ")
        require(total_input > total_output, "Actual fee must be positive")
        counts = self.proxy.snapshot()
        require(counts["send_attempts"] == counts["forwarded_submits"] == counts["accepted_submits"] == 1,
                "Exactly one actual node submission required")
        blockhash = tx.get("blockhash") if tx.get("confirmations", 0) > 0 else None
        header = self.rpc.call("getblockheader", [blockhash, True]) if blockhash else None
        return {"txid": txid, "destination": destination, "output_sat": total_output, "total_input_sat": total_input,
                "fee_sat": total_input - total_output, "vsize": tx["vsize"], "input_count": len(inputs),
                "confirmations": tx.get("confirmations", 0), "block_hash": blockhash,
                "block_height": header["height"] if header else None, "inputs": inputs, "outputs": outputs,
                **{k: counts[k] for k in ["send_attempts", "forwarded_submits", "accepted_submits"]}}

    def action(self, name, params):
        require(isinstance(params, dict), "IPC params must be an object")
        if name in {"snapshot_counts", "arm_drop_next_submit_reply", "stop_backend", "start_backend", "restart_backend"}:
            require(not params, "Unexpected IPC parameters")
            if name == "snapshot_counts":
                return self.snapshot()
            if name == "arm_drop_next_submit_reply":
                with self.proxy.lock:
                    require(not self.proxy.drop_next, "Submit ACK loss already armed")
                    self.proxy.drop_next = True
                return {"armed": True}
            if name == "stop_backend":
                return self.stop_backend()
            if name == "restart_backend":
                self.stop_backend()
            return self.start_backend()
        if name == "status_outage":
            require(set(params) == {"enabled"} and type(params["enabled"]) is bool, "Invalid outage params")
            with self.proxy.lock:
                self.proxy.outage = params["enabled"]
            return {"enabled": params["enabled"]}
        if name == "verify_transaction":
            require(set(params) == {"txid", "destination", "expected_output_sat"}, "Invalid transaction params")
            return self.verify_transaction(**params)
        if name == "mine":
            require(set(params) == {"blocks"} and type(params["blocks"]) is int and params["blocks"] == 1,
                    "Only one owned regtest block may be mined per action")
            require(self.rpc.call("getblockchaininfo")["chain"] == "regtest", "Wrong mining chain")
            mining_address = self.rpc.call("getnewaddress", ["", "bech32"], self.wallet)
            blockhash = self.rpc.call("generatetoaddress", [1, mining_address])[0]
            return {"blocks": 1, "height": self.rpc.call("getblockcount"), "block_hash": blockhash,
                    "mempool_txids": self.rpc.call("getrawmempool")}
        if name == "reorg_last_confirmation":
            require(set(params) == {"txid"} and re.fullmatch(r"[0-9a-f]{64}", params["txid"] or ""), "Invalid reorg params")
            tx = self.rpc.call("getrawtransaction", [params["txid"], True])
            require(params["txid"] == self.proxy.snapshot()["last_submitted_txid"] and
                    self.rpc.call("getblockchaininfo")["chain"] == "regtest", "Unrecognized reorg target/chain")
            require(tx.get("confirmations") == 1 and tx.get("blockhash") == self.rpc.call("getbestblockhash"),
                    "Only the owned transaction's first tip confirmation may be invalidated")
            self.rpc.call("invalidateblock", [tx["blockhash"]])
            return {"txid": params["txid"], "confirmations": self.rpc.call("getrawtransaction", [params["txid"], True]).get("confirmations", 0),
                    "height": self.rpc.call("getblockcount"), "mempool_txids": self.rpc.call("getrawmempool")}
        raise Failure("Unknown IPC action")

    def run(self):
        sources = [Path(__file__), ROOT / "native/macos/Puzzle71.swift",
                   ROOT / "native/macos/tests/WalletRegtestTests.swift"]
        tracked = subprocess.check_output(["git", "ls-files"], cwd=ROOT, env=self.env, text=True).splitlines()
        all_sources = sorted({*tracked, *(str(p.relative_to(ROOT)) for p in sources)})
        self.report["sources_before"] = {p: digest(ROOT / p) for p in all_sources}
        self.report["rehearsal"] = {"path": str(self.args.rehearsal_bin), "sha256": digest(self.args.rehearsal_bin),
            "source_binding_limit": "Explicit caller-built artifact; match this hash with its separate Rust build provenance."}
        native = self.output / "build/NativeWalletRegtest"
        self.command("compile-swift", ["/usr/bin/nice", "-n", "15", "xcrun", "swiftc", "-parse-as-library",
            "-D", "PUZZLE71_TESTING", "-O", "-num-threads", "1", "-target", platform.machine() + "-apple-macos14.0",
            "-framework", "AppKit", "-framework", "WebKit", "-warnings-as-errors", str(sources[1]), str(sources[2]), "-o", str(native)], timeout=180)
        declared = json.loads(self.command("list-cases", [str(native), "--list-cases"]))
        require(declared["schema"] == 1, "Unknown native case-list schema")
        require(declared["case_ids"][:len(declared["keystone_case_ids"])] == declared["keystone_case_ids"] and
                0 < len(declared["keystone_case_ids"]) < len(declared["case_ids"]), "Invalid early-keystone catalog")
        expected = declared["keystone_case_ids" if self.args.keystone_only else "case_ids"]
        require(isinstance(expected, list) and expected and len(expected) == len(set(expected)) and
                all(isinstance(x, str) and x for x in expected), "Missing or duplicate native case IDs")
        self.report["native_binary_sha256"] = digest(native)
        self.report["expected_case_ids"] = expected
        self.report["expected_case_count"] = len(expected)
        self.report["full_catalog_case_count"] = len(declared["case_ids"])
        self.setup_node()
        fixture_address = self.command("write-public-fixture", [str(self.args.rehearsal_bin), "write-hit", "--dir", str(self.backend_dir)]).strip()
        require(self.rpc.call("validateaddress", [fixture_address])["isvalid"], "Invalid regtest fixture address")
        self.rpc.call("createwallet", [self.wallet])
        self.mining_address = self.rpc.call("getnewaddress", ["", "bech32"], self.wallet)
        self.rpc.call("generatetoaddress", [101, self.mining_address])
        funding_txid = self.rpc.call("sendtoaddress", [fixture_address, 8], self.wallet)
        self.rpc.call("generatetoaddress", [1, self.mining_address])
        self.destinations = [self.rpc.call("getnewaddress", ["", address_type], self.wallet) for address_type in ["bech32", "bech32m"]]
        require(not self.rpc.call("getrawmempool"), "Initial funding mempool must be empty")
        unspent = self.rpc.call("scantxoutset", ["start", ["addr(" + fixture_address + ")"]])
        require(unspent["success"] and len(unspent["unspents"]) == 1 and satoshis(unspent["total_amount"]) == FUNDING_SAT,
                "Fixture funding must be exactly one confirmed8BTC UTXO")
        self.report["fixture"] = {"address": fixture_address, "funding_txid": funding_txid,
                                  "funding_sat": FUNDING_SAT, "destination_a": self.destinations[0], "destination_b": self.destinations[1]}
        self.proxy = FaultProxy(self.rpc)
        self.proxy.thread.start()
        self.backend_port = free_port()
        self.start_backend()
        result_path = self.output / "driver-results.json"
        config = {"backend_url": f"http://127.0.0.1:{self.backend_port}", "destination_a": self.destinations[0],
            "destination_b": self.destinations[1], "control_dir": str(self.control), "results_path": str(result_path),
            "screenshots_dir": str(self.output / "screenshots"), "expected_funding_sat": FUNDING_SAT,
            "keystone_only": self.args.keystone_only}
        config_path = self.private / "native-config.json"
        atomic_json(config_path, config)
        self.native = Child([str(native), str(config_path)], ROOT, self.env, self.private, "native-driver", self.output / "logs")
        self.children.append(self.native)
        sequence, deadline = 1, time.monotonic() + self.args.timeout
        while self.native.process.poll() is None:
            require(time.monotonic() < deadline, "Native wallet test timed out")
            request_path = self.control / f"request-{sequence:04d}.json"
            if request_path.exists() or request_path.is_symlink():
                request = bounded_json(request_path, 16384)
                require(set(request) == {"sequence", "action", "params"} and type(request["sequence"]) is int and request["sequence"] == sequence,
                        "IPC sequence/schema differs")
                began = now()
                try:
                    result = self.action(request["action"], request["params"])
                    response = {"sequence": sequence, "ok": True, "result": result}
                except Exception as error:
                    response = {"sequence": sequence, "ok": False,
                                "error": {"code": type(error).__name__, "message": "Owned regtest action failed"}}
                response_path = self.control / f"response-{sequence:04d}.json"
                require(not response_path.exists(), "IPC response already exists")
                atomic_json(response_path, response)
                self.report["actions"].append({"sequence": sequence, "action": request["action"],
                    "started_at": began, "finished_at": now(), "response": response})
                self.persist()
                print("native-regtest action " + str(sequence) + ": " + str(request["action"]), flush=True)
                sequence += 1
                require(sequence <= 1000, "Too many IPC actions")
            time.sleep(0.02)
        self.record_child(self.native)
        results = bounded_json(result_path)
        self.report["native_case_counts"] = native_case_counts(expected, results)
        self.report["native_cases"] = results["cases"]
        require(self.native.process.returncode == 0, "Native driver exited unsuccessfully")
        require(results.get("schema") == 1 and results.get("passed") is True and not results.get("errors"), "Native result not successful")
        cases = results.get("cases", [])
        require([case.get("id") for case in cases] == expected and all(case.get("passed") is True for case in cases),
                "Native cases missing, duplicated, reordered or failed")
        require(all(row["response"]["ok"] for row in self.report["actions"]), "An IPC action failed")
        counts = self.proxy.snapshot()
        require(counts["send_attempts"] == counts["forwarded_submits"] == counts["accepted_submits"] == counts["dropped_submit_replies"] == 1,
                "Expected exactly one actual accepted submission and one deliberately lost ACK")
        require(any(row["action"] == "verify_transaction" and row["response"]["ok"] for row in self.report["actions"]),
                "Missing independent Core transaction verification")
        self.report.update(native_cases=cases, final_proxy_counts=counts, passed=True)
        self.report["sources_after"] = {p: digest(ROOT / p) for p in all_sources}
        require(self.report["sources_after"] == self.report["sources_before"], "Native test sources changed during run")
        require(digest(self.args.rehearsal_bin) == self.report["rehearsal"]["sha256"], "Rehearsal artifact changed")

    def cleanup(self):
        errors = []
        for child in self.children[:]:
            if child is not self.tunnel:
                try:
                    child.stop()
                    self.record_child(child)
                except Exception as error:
                    errors.append(type(error).__name__ + ": own child cleanup failed")
        if self.proxy:
            try:
                self.proxy.close()
            except Exception:
                errors.append("Own proxy cleanup failed")
        if self.node_create_attempted and self.container_id is None:
            try:
                candidates = self.command("find-own-node", self.docker_argv([
                    "ps", "-aq", "--no-trunc", "--filter", "name=^/" + self.name + "$",
                    "--filter", "label=p71.native-regtest-run=" + self.token])).split()
                require(len(candidates) <= 1, "Multiple containers have this run's private ownership label")
                if candidates:
                    require(re.fullmatch(r"[0-9a-f]{64}", candidates[0]), "Invalid recovered container ID")
                    self.container_id = candidates[0]
                else:
                    errors.append("Container creation outcome unknown; retain unique name/label for manual review")
            except Exception:
                errors.append("Cannot reconcile this run's container creation outcome")
        if self.container_id:
            try:
                self.inspect_owned()
                self.command("node-stop", self.docker_argv(["stop", "--time", "20", self.container_id]), timeout=45)
                remaining = self.command("node-absence", self.docker_argv(["ps", "-aq", "--filter", "label=p71.native-regtest-run=" + self.token])).strip()
                require(not remaining, "Owned --rm container still exists")
                self.report["own_container_removed"] = True
            except Exception:
                errors.append("Own container cleanup failed; retain recorded ID for manual review")
        if self.tunnel:
            try:
                self.tunnel.stop()
                self.record_child(self.tunnel)
                require(port_free(self.rpc.port), "Own RPC forward port still occupied")
            except Exception:
                errors.append("Own RPC tunnel cleanup failed")
        all_exited = all(child.process.poll() is not None for child in self.children)
        self.report["cleanup"] = {"errors": errors, "all_owned_children_exited": all_exited,
                                  "backend_port_free": port_free(self.backend_port), "private_tempdir_removed": False}
        if all_exited and not errors:
            meta = self.private.lstat()
            require(stat.S_ISDIR(meta.st_mode) and (meta.st_dev, meta.st_ino) == self.private_identity and meta.st_uid == os.getuid(),
                    "Private temp directory identity changed; refuse removal")
            shutil.rmtree(self.private)
            self.report["cleanup"]["private_tempdir_removed"] = True
        require(all_exited and not errors and self.report["cleanup"]["backend_port_free"], "Owned cleanup incomplete")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rehearsal-bin", required=True, type=Path)
    parser.add_argument("--docker-ssh-host", help="Optional SSH host/alias; no Docker context is changed")
    parser.add_argument("--output", required=True, type=Path, help="Fresh private evidence directory")
    parser.add_argument("--keystone-only", action="store_true", help="Only the driver's initial real prepare/send/Core cases")
    parser.add_argument("--timeout", type=int, default=600, help="Maximum native-driver runtime in seconds")
    args = parser.parse_args()
    require(sys.platform == "darwin" and os.getuid() != 0, "Run as a macOS GUI user")
    require(60 <= args.timeout <= 1800, "Timeout must be60..1800seconds")
    require(args.docker_ssh_host is None or re.fullmatch(r"(?:[A-Za-z0-9_][A-Za-z0-9_.-]*@)?[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", args.docker_ssh_host),
            "Invalid SSH host/alias")
    args.rehearsal_bin = args.rehearsal_bin.expanduser().resolve(strict=True)
    require(args.rehearsal_bin.is_file() and os.access(args.rehearsal_bin, os.X_OK), "Rehearsal binary must be executable")
    supervisor = Supervisor(args)
    def interrupted(signum, _frame):
        raise Failure("Native regtest interrupted by signal " + str(signum))
    previous = {sig: signal.signal(sig, interrupted) for sig in [signal.SIGINT, signal.SIGTERM, signal.SIGHUP]}
    try:
        supervisor.run()
    except Exception as error:
        supervisor.report.update(passed=False, failure={"type": type(error).__name__, "message": str(error) if isinstance(error, Failure) else "Owned test infrastructure failure"})
    finally:
        try:
            supervisor.cleanup()
        except Exception as error:
            supervisor.report.update(passed=False, cleanup_failure=type(error).__name__)
        supervisor.report["finished_at"] = now()
        supervisor.persist()
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    print(json.dumps({"passed": supervisor.report["passed"], "evidence": str(supervisor.output / "evidence.json"),
                      "mode": supervisor.report["mode"], "expected_cases": supervisor.report.get("expected_case_count"),
                      "case_counts": supervisor.report.get("native_case_counts"),
                      "native_cases": len(supervisor.report.get("native_cases", [])), "cleanup": supervisor.report.get("cleanup")}), flush=True)
    raise SystemExit(0 if supervisor.report["passed"] else 1)


if __name__ == "__main__":
    main()
