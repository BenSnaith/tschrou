import argparse
import hashlib
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

class ChordClient:
    FIND_SUCCESSOR_REQ = 0x01
    FIND_SUCCESSOR_RESP = 0x02
    PING = 0x07
    PONG = 0x08
    GET_REQ = 0x10
    GET_RESP = 0x11
    PUT_REQ = 0x12
    PUT_RESP = 0x13

    TIMEOUT = 1.0

    @staticmethod
    def hash_key(key: str) -> int:
        digest = hashlib.sha1(key.encode()).digest()
        return int.from_bytes(digest[:4], byteorder="little")

    @staticmethod
    def _encode_string(s: str) -> bytes:
        encoded = s.encode()
        return struct.pack(">I", len(encoded)) + encoded

    @staticmethod
    def _decode_string(data: bytes, offset: int) -> tuple[str, int]:
        length = struct.unpack(">I", data[offset:offset + 4])[0]
        offset += 4
        s = data[offset:offset + length].decode()
        offset += length
        return s, offset

    @staticmethod
    def _send_recv(host: str, port: int, payload: bytes) -> Optional[bytes]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(ChordClient.TIMEOUT)
            sock.connect((host, port))
            sock.sendall(payload)
            data = sock.recv(4096)
            sock.close()
            return data if data else None
        except Exception:
            return None

    @staticmethod
    def ping(host: str, port: int) -> bool:
        resp = ChordClient._send_recv(host, port, bytes([ChordClient.PING]))
        return resp is not None and len(resp) >= 1 and resp[0] == ChordClient.PONG

    @staticmethod
    def find_successor(host: str, port: int, key_id: int) -> Optional[tuple[int, str, int]]:
        payload = bytes([ChordClient.FIND_SUCCESSOR_REQ]) + struct.pack(">I", key_id)
        resp = ChordClient._send_recv(host, port, payload)

        if resp is None or len(resp) < 2:
            return None

        if resp[0] != ChordClient.FIND_SUCCESSOR_RESP:
            return None

        found = resp[1]
        if not found:
            return None

        offset = 2
        node_id = struct.unpack(">I", resp[offset:offset + 4])[0]
        offset += 4
        ip, offset = ChordClient._decode_string(resp, offset)
        node_port = struct.unpack(">H", resp[offset:offset + 2])[0]
        return (node_id, ip, node_port)

    @staticmethod
    def put(host: str, port: int, key: str, value: str) -> bool:
        payload = (bytes([ChordClient.PUT_REQ])
                   + ChordClient._encode_string(key)
                   + ChordClient._encode_string(value))
        resp = ChordClient._send_recv(host, port, payload)
        if resp is None or len(resp) < 2:
            return False
        return resp[0] == ChordClient.PUT_RESP and resp[1] != 0

    @staticmethod
    def get(host: str, port: int, key: str) -> Optional[str]:
        payload = (bytes([ChordClient.GET_REQ])
                   + ChordClient._encode_string(key))
        resp = ChordClient._send_recv(host, port, payload)
        if resp is None or len(resp) < 2:
            return None
        if resp[0] != ChordClient.GET_RESP:
            return None
        found = resp[1]
        if not found:
            return None
        value, _ = ChordClient._decode_string(resp, 2)
        return value

DEFAULT_PORT = 11000
STABILISE_WAIT = 6             # seconds to wait for ring to stabilise
ATTACK_DURATION = 10           # seconds to run after the attack
METRICS_DELAY = 2              # seconds to wait after attack before collecting metrics
NUM_LEGIT_NODES = 5
NUM_MALICIOUS_NODES = 10       # for eclipse/sybil attacks
NUM_TEST_KEYS = 500            # key-value pairs for integrity testing
NUM_RUNS = 3                   # num of runs to average out scenarios
VERBOSE = False

@dataclass
class ScenarioResult:
    scenario_name: str
    security_flags: list[str]
    attack_type: str
    keys_stored: int = 0
    keys_retrieved: int = 0
    keys_correct: int = 0
    lookup_success_rate: float = 0.0
    lookup_success_rate_std: float = 0.0
    module_metrics: dict = field(default_factory=dict)
    duration_seconds: float = 0.0
    runs: list = field(default_factory=list)

@dataclass
class Scenario:
    name: str
    security_flags: list[str]
    attack_type: str
    num_sybil: int = 0
    description: str = ""
    pre_store_attack: bool = False
    sybil_flags: list[str] = field(default_factory=list)


SCENARIOS = {
    # baseline
    "baseline_no_security": Scenario(
        name="baseline_no_security",
        security_flags=[],
        attack_type="none",
        description="Normal ring, no security modules",
    ),
    "baseline_all_security": Scenario(
        name="baseline_all_security",
        security_flags=["--all-security"],
        attack_type="none",
        description="Normal ring, all security modules enabled",
    ),
    # sybil attacks
    "sybil_spoof_no_defence": Scenario(
        name="sybil_spoof_no_defence",
        security_flags=[],
        attack_type="sybil",
        num_sybil=NUM_MALICIOUS_NODES,
        sybil_flags=["--spoof-id"],
        description="Sybil attack with spoofed IDs, no defence",
    ),
    "sybil_spoof_id_verify": Scenario(
        name="sybil_spoof_id_verify",
        security_flags=["--id-verify"],
        attack_type="sybil",
        num_sybil=NUM_MALICIOUS_NODES,
        sybil_flags=["--spoof-id"],
        description="Sybil attack with spoofed IDs, IDVerification enabled",
    ),
    "sybil_lookup_validate": Scenario(
        name="sybil_lookup_validate",
        security_flags=["--lookup-validate"],
        attack_type="sybil",
        num_sybil=NUM_MALICIOUS_NODES,
        description="Sybil attack with lookup validation",
    ),
    "sybil_subnet_diversity": Scenario(
        name="sybil_subnet_diversity",
        security_flags=["--subnet-diversity", "--subnet-max", "2"],
        attack_type="sybil",
        num_sybil=NUM_MALICIOUS_NODES,
        description="Sybil attack with subnet diversity (max 2 per /24)",
    ),
    "sybil_all_defence": Scenario(
        name="sybil_all_defence",
        security_flags=["--id-verify", "--subnet-diversity", "--subnet-max", "2",
                        "--peer-age", "--age-min", "3"],
        attack_type="sybil",
        num_sybil=NUM_MALICIOUS_NODES,
        description="Sybil attack with combined defences (id_verify + subnet + peer_age)",
    ),
    # eclipse attacks
    "eclipse_no_defence": Scenario(
        name="eclipse_no_defence",
        security_flags=[],
        attack_type="eclipse",
        num_sybil=NUM_MALICIOUS_NODES,
        pre_store_attack=True,
        description="Eclipse attack targeting one node, no defences",
    ),
    "eclipse_peer_age": Scenario(
        name="eclipse_peer_age",
        security_flags=["--peer-age", "--age-min", "5"],
        attack_type="eclipse",
        num_sybil=NUM_MALICIOUS_NODES,
        pre_store_attack=True,
        description="Eclipse attack with peer age preference",
    ),
    "eclipse_all_defence": Scenario(
        name="eclipse_all_defence",
        security_flags=["--id-verify", "--peer-age", "--age-min", "3"],
        attack_type="eclipse",
        num_sybil=NUM_MALICIOUS_NODES,
        pre_store_attack=True,
        description="Eclipse attack with combined defences (id_verify + peer_age)",
    ),
    # dos attacks
    "dos_no_defence": Scenario(
        name="dos_no_defence",
        security_flags=[],
        attack_type="dos",
        pre_store_attack=True,
        description="DoS flood during store and retrieve, no defences",
    ),
    "dos_rate_limit": Scenario(
        name="dos_rate_limit",
        security_flags=["--rate-limit"],
        attack_type="dos",
        pre_store_attack=True,
        description="DoS flood during store and retrieve, with rate limiting",
    ),
}

class NodeProcess:
    def __init__(self, binary: str, port: int, mode: str,
                 known_addr: Optional[str] = None,
                 security_flags: Optional[list[str]] = None,
                 ip: str = "127.0.0.1"):
        self.binary = binary
        self.port = port
        self.ip = ip
        self.mode = mode
        self.known_addr = known_addr
        self.security_flags = security_flags or []
        self.process: Optional[subprocess.Popen] = None

    def start(self) -> bool:
        cmd = [self.binary, self.mode, str(self.port)]
        if self.mode == "join" and self.known_addr:
            cmd.append(self.known_addr)
        cmd.extend(self.security_flags)
        cmd.extend(["--ip", self.ip])

        if VERBOSE:
            print(f"    [CMD] {' '.join(cmd)}")

        try:
            self.process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=None if VERBOSE else subprocess.DEVNULL,
                text=True,
            )
            # wait to bind
            time.sleep(0.3)
            if self.process.poll() is not None:
                if not VERBOSE and self.process.stderr:
                    stderr = self.process.stderr.read()
                    print(f"[FAIL] Node on port {self.port} exited: {stderr}")
                else:
                    print(f"[FAIL] Node on port {self.ip}:{self.port} exited immediately")
                return False
            return True
        except Exception as e:
            print(f"[FAIL] Could not start node on port {self.port}: {e}")
            return False

    def send_command(self, cmd: str) -> str:
        if not self.process or self.process.poll() is not None:
            return ""
        try:
            self.process.stdin.write(cmd + "\n")
            self.process.stdin.flush()
            time.sleep(0.2)
            return ""
        except Exception:
            return ""

    def get_metrics(self) -> dict:
        if not self.process or self.process.poll() is not None:
            return {}
        try:
            self.process.stdin.write("metrics\n")
            self.process.stdin.flush()
            time.sleep(1.0)

            raw = self.process.stdout.buffer.read1(65536).decode("utf-8", errors="replace")
            for line in raw.splitlines():
                if line.strip().startswith("METRICS:"):
                    return json.loads(line.strip()[len("METRICS:"):])
        except Exception as e:
            print(f"[WARN] Failed to get metrics from port {self.port}: {e}")
        return {}

    def put(self, key: str, value: str):
        self.send_command(f"put {key} {value}")

    def get(self, key: str) -> Optional[str]:
        self.send_command(f"get {key}")
        return None

    def stop(self):
        if self.process and self.process.poll() is None:
            try:
                self.process.stdin.write("quit\n")
                self.process.stdin.flush()
                self.process.wait(timeout=3)
            except Exception:
                self.process.kill()
                self.process.wait()

class TestRing:
    def __init__(self, binary: str, base_port: int,
                 security_flags: list[str]):
        self.binary = binary
        self.base_port = base_port
        self.security_flags = security_flags
        self.nodes: list[NodeProcess] = []

    def create_ring(self, num_nodes: int) -> bool:
        print(f"Creating a ring with {num_nodes} nodes (ports {self.base_port}-{self.base_port+num_nodes-1})")

        creator_ip = "127.0.0.1"
        creator = NodeProcess(
            self.binary, self.base_port, "create",
            security_flags=self.security_flags,
            ip=creator_ip
        )
        if not creator.start():
            return False
        self.nodes.append(creator)

        known_addr = f"127.0.0.1:{self.base_port}"
        for i in range(1, num_nodes):
            port = self.base_port + i
            node_ip = f"127.0.0.{i + 1}"
            joiner = NodeProcess(
                self.binary, port, "join",
                known_addr=known_addr,
                security_flags=self.security_flags,
                ip=node_ip
            )
            if not joiner.start():
                print(f"[WARN] Node on port {port} failed to start, continuing")
            else:
                self.nodes.append(joiner)
            time.sleep(0.3)

        print(f"Waiting {STABILISE_WAIT}s for stabilisation...")
        time.sleep(STABILISE_WAIT)
        return True

    def add_sybil_nodes(self, count: int,
                        sybil_flags: Optional[list[str]] = None) ->list[NodeProcess]:
        sybil_nodes = []
        known_addr = f"127.0.0.1:{self.base_port}"
        start_port = self.base_port + len(self.nodes)

        print(f" Injecting {count} Sybil Nodes (ports {start_port}-{start_port + count - 1})")

        for i in range(count):
            port = start_port + i
            sybil_ip = f"127.0.1.{i + 1}"
            flags = list(sybil_flags or []) + ["--malicious"]
            node = NodeProcess(
                self.binary, port, "join",
                known_addr=known_addr,
                security_flags=flags,
                ip = sybil_ip
            )
            if node.start():
                sybil_nodes.append(node)
                self.nodes.append(node)
            time.sleep(0.1)

        time.sleep(STABILISE_WAIT)
        return sybil_nodes

    def store_test_data(self, num_keys: int) -> dict[str, str]:
        test_data = {}
        stored = 0
        for i in range(num_keys):
            key = f"test_key_{i}"
            value = f"test_value_{i}"
            test_data[key] = value
            if ChordClient.put("127.0.0.1", self.base_port, key, value):
                stored += 1
            time.sleep(0.05)

        print(f"Stored {num_keys} test key-value pairs")
        time.sleep(1)
        return test_data

    def verify_data(self, test_data: dict[str, str]) -> tuple[int, int]:
        retrieved = 0
        correct = 0

        for key, expected_value in test_data.items():
            result = ChordClient.get("127.0.0.1", self.base_port, key)
            if result is not None:
                retrieved += 1
                if result == expected_value:
                    correct += 1
                elif VERBOSE:
                    print(f"    [WRONG] {key}: expected '{expected_value}', got '{result}'")
            elif VERBOSE:
                print(f"    [MISS] {key}: lookup failed or not found")

        print(f"Verified: {correct}/{len(test_data)} correct")
        print(f"{retrieved}/{len(test_data)} retrieved")
        return retrieved, correct

    def collect_metrics(self) -> list[dict]:
        all_metrics = []
        for i, node in enumerate(self.nodes[: NUM_LEGIT_NODES]):
            metrics = node.get_metrics()
            if metrics:
                all_metrics.append(
                    {
                        "node_index": i,
                        "port": node.port,
                        "metrics": metrics,
                    }
                )
        return all_metrics

    def teardown(self):
        print(f"Tearing down {len(self.nodes)} nodes...")
        for node in self.nodes:
            node.stop()
        self.nodes.clear()
        if hasattr(self, '_flood_stop'):
            self._flood_stop.set()
            for t in self._flood_threads:
                t.join(timeout=2)
        time.sleep(1)

def attack_none(ring: TestRing):
    print(f"No attack (baseline)")

def attack_sybil(ring: TestRing, num_sybil: int, sybil_flags: list[str] = None):
      ring.add_sybil_nodes(num_sybil, sybil_flags=sybil_flags)

def attack_eclipse(ring: TestRing, num_sybil: int, sybil_flags: list[str] = None):
      ring.add_sybil_nodes(num_sybil, sybil_flags=sybil_flags)

def attack_dos(ring: TestRing):
    import threading
    target_port = ring.base_port
    stop_event = threading.Event()

    def flood():
        while not stop_event.is_set():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            try:
                sock.bind(("127.0.0.254", 0))
                sock.connect(("127.0.0.1", target_port))
                sock.sendall(bytes([0x01, 0x00, 0x00, 0x00, 0x42, 0x00]))
            except Exception:
                pass
            finally:
                sock.close()
            time.sleep(0.01)

    threads = []
    for _ in range(10):
        t = threading.Thread(target=flood, daemon=True)
        t.start()
        threads.append(t)

    print(f"Flooding port {target_port} with 10 concurrent threads...")
    ring._flood_stop = stop_event
    ring._flood_threads = threads



ATTACK_FUNCTIONS = {
      "none":    lambda ring, scenario: attack_none(ring),
      "sybil":   lambda ring, scenario: attack_sybil(ring, scenario.num_sybil,
                                                      scenario.sybil_flags or None),
      "eclipse": lambda ring, scenario: attack_eclipse(ring, scenario.num_sybil,
                                                       scenario.sybil_flags or None),
      "dos":     lambda ring, scenario: attack_dos(ring),
  }


def run_scenario(binary: str, scenario: Scenario,
                 port_offset: int = 0) -> ScenarioResult:
    print(f"{'=' * 60}")
    print(f"SCENARIO: {scenario.name}")
    print(f"\tAttack: {scenario.attack_type}")
    print(f"\tSecurity: {scenario.security_flags or '(none)'}")
    print(f"\tDescription: {scenario.description}")
    print(f"{'=' * 60}")

    base_port = DEFAULT_PORT + port_offset
    start_time = time.time()

    ring = TestRing(binary, base_port, scenario.security_flags)
    result = ScenarioResult(
        scenario_name=scenario.name,
        security_flags=scenario.security_flags,
        attack_type=scenario.attack_type,
    )

    try:
        if not ring.create_ring(NUM_LEGIT_NODES):
            print(f"[FAIL] Could not create ring")
            return result

        attack_fn = ATTACK_FUNCTIONS.get(scenario.attack_type)

        if scenario.pre_store_attack and attack_fn:
            attack_fn(ring, scenario)

        test_data = ring.store_test_data(NUM_TEST_KEYS)
        result.keys_stored = len(test_data)

        if not scenario.pre_store_attack and attack_fn:
            attack_fn(ring, scenario)

        time.sleep(METRICS_DELAY)

        retrieved, correct = ring.verify_data(test_data)
        result.keys_retrieved = retrieved
        result.keys_correct = correct
        result.lookup_success_rate = correct / max(len(test_data), 1)

        metrics = ring.collect_metrics()
        result.module_metrics = metrics
    finally:
        ring.teardown()

    result.duration_seconds = time.time() - start_time
    print(f"Completed in {result.duration_seconds:.1f}s")
    return result

import statistics as _stats

def _avg_module_metrics(all_runs_metrics: list[list[dict]]) -> list[dict]:
    """Average module counter/gauge values across runs, per node."""
    if not all_runs_metrics or not all_runs_metrics[0]:
        return []
    averaged = []
    for node_idx in range(len(all_runs_metrics[0])):
        node_runs = [rm[node_idx] for rm in all_runs_metrics
                     if node_idx < len(rm)]
        if not node_runs:
            continue
        base = node_runs[0]
        avg_modules = []
        for mod_idx in range(len(base["metrics"].get("modules", []))):
            mod_runs = [nr["metrics"]["modules"][mod_idx]
                        for nr in node_runs
                        if mod_idx < len(nr["metrics"].get("modules", []))]
            if not mod_runs:
                continue
            avg_counters = {
                k: round(_stats.mean(mr["counters"].get(k, 0)
                                     for mr in mod_runs), 1)
                for k in mod_runs[0]["counters"]
            }
            avg_gauges = {
                k: round(_stats.mean(mr["gauges"].get(k, 0)
                                     for mr in mod_runs), 1)
                for k in mod_runs[0]["gauges"]
            }
            avg_modules.append({
                "name": mod_runs[0]["name"],
                "counters": avg_counters,
                "gauges": avg_gauges,
            })
        averaged.append({
            "node_index": base["node_index"],
            "port": base["port"],
            "metrics": {"modules": avg_modules},
        })
    return averaged


def average_results(run_list: list[ScenarioResult]) -> ScenarioResult:
    rates = [r.lookup_success_rate for r in run_list]
    result = ScenarioResult(
        scenario_name=run_list[0].scenario_name,
        security_flags=run_list[0].security_flags,
        attack_type=run_list[0].attack_type,
        keys_stored=round(_stats.mean(r.keys_stored for r in run_list)),
        keys_retrieved=round(_stats.mean(r.keys_retrieved for r in run_list)),
        keys_correct=round(_stats.mean(r.keys_correct for r in run_list)),
        lookup_success_rate=_stats.mean(rates),
        lookup_success_rate_std=_stats.stdev(rates) if len(rates) > 1 else 0.0,
        duration_seconds=_stats.mean(r.duration_seconds for r in run_list),
        module_metrics=_avg_module_metrics([r.module_metrics for r in run_list]),
        runs=[
            {
                "run": i + 1,
                "keys_retrieved": r.keys_retrieved,
                "keys_correct": r.keys_correct,
                "lookup_success_rate": r.lookup_success_rate,
                "duration_seconds": r.duration_seconds,
            }
            for i, r in enumerate(run_list)
        ],
    )
    return result

def save_results_json(results: list[ScenarioResult], output_dir: str = "results"):
    os.makedirs(output_dir, exist_ok=True)

    data = []
    for r in results:
        data.append({
            "scenario": r.scenario_name,
            "attack_type": r.attack_type,
            "security_flags": r.security_flags,
            "keys_stored": r.keys_stored,
            "keys_retrieved": r.keys_retrieved,
            "keys_correct": r.keys_correct,
            "lookup_success_rate": r.lookup_success_rate,
            "lookup_success_rate_std": r.lookup_success_rate_std,
            "duration_seconds": r.duration_seconds,
            "module_metrics": r.module_metrics,
            "runs": r.runs,
        })

    path = f"{output_dir}/result-{time.time_ns()}.json"
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Saved: {path}")

def main():
    parser = argparse.ArgumentParser(
        description="Chord DHT Security Test Harness"
    )
    parser.add_argument(
        "--binary", required=True,
        help="Path to the compile chord binary"
    )
    parser.add_argument(
        "--scenarios", default="all",
        help="Comma-separated scenario names, or 'all' (default: all)"
    )
    parser.add_argument(
        "--output", default="results",
        help="Output directory for results (default: results)"
    )
    parser.add_argument(
        "--list", action="store_true",
        help="List available scenarios and exit"
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Show node stderr output for debugging"
    )

    args = parser.parse_args()

    global VERBOSE
    VERBOSE = args.verbose

    if args.list:
        print("Available Scenarios")
        for name, scenario in SCENARIOS.items():
            flags = " ".join(scenario.security_flags) or "(none)"
            print(f"{name:30s} attack={scenario.attack_type:8s} flags={flags}")
        return

    if args.scenarios == "all":
        selected = list(SCENARIOS.values())
    else:
        names = [n.strip() for n in args.scenarios.split(",")]
        selected = []
        for name in names:
            if name in SCENARIOS:
                selected.append(SCENARIOS[name])
            else:
                print(f"Unknown Scenario: {name}")
                print(f"Available: {', '.join(SCENARIOS.keys())}")
                return

    if not os.path.isfile(args.binary):
        print(f"Binary not found {args.binary}")
        return

    print("Running Scenarios")
    print(f"Output {args.output}/")

    results = []
    # for i, scenario in enumerate(selected):
    #     port_offset = i * 100
    #     result = run_scenario(args.binary, scenario, port_offset)
    #     results.append(result)

    for scenario in selected:
        run_list = []
        for run_num in range(1, NUM_RUNS + 1):
            print(f"\n[Run {run_num}/{NUM_RUNS}] {scenario.name}")
            result = run_scenario(args.binary, scenario, port_offset=0)
            run_list.append(result)
            print(f"  -> {result.lookup_success_rate*100:.1f}%")
        averaged = average_results(run_list)
        print(f"  AVERAGE: {averaged.lookup_success_rate*100:.1f}% "
              f"(±{averaged.lookup_success_rate_std*100:.1f}%)")
        results.append(averaged)

    print(f"\n{'=' * 60}")
    print("GENERATING RESULTS")
    print(f"{'=' * 60}")

    save_results_json(results, args.output)

    print(f"\n{'=' * 60}")
    print("SUMMARY")
    print(f"{'=' * 60}")
    for r in results:
        print(
            f"{r.scenario_name:<35} {r.attack_type:<10}"
            f"{r.lookup_success_rate*100:>6.1f}%"   
            f"{r.duration_seconds:>6.1f}s"
        )
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
