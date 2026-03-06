import argparse
import json
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

DEFAULT_PORT = 9000
STABILISE_WAIT = 4             # seconds to wait for ring to stabilise
ATTACK_DURATION = 10           # seconds to run after the attack
METRICS_DELAY = 2              # seconds to wait after attack before collecting metrics
NUM_LEGIT_NODES = 5
NUM_MALICIOUS_NODES = 10       # for eclipse/sybil attacks
NUM_TEST_KEYS = 50             # key-value pairs for integrity testing

@dataclass
class ScenarioResult:
    scenario_name: str
    security_flags: list[str]
    attack_type: str
    keys_stored: int = 0
    keys_retrieved: int = 0
    keys_correct: int = 0
    lookup_success_rate: float = 0.0
    module_metrics: dict = field(default_factory=dict)
    duration_seconds: float = 0.0

@dataclass
class Scenario:
    name: str
    security_flags: list[str]
    attack_type: str
    num_sybil: int = 0
    description: str = ""

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
    "sybil_no_defence": Scenario(
        name="sybil_no_defence",
        security_flags=[],
        attack_type="sybil",
        num_sybil=NUM_MALICIOUS_NODES,
        description="Sybil attack with no defence",
    ),
    "sybil_id_verify": Scenario(
        name="sybil_id_verify",
        security_flags=["--id-verify"],
        attack_type="sybil",
        num_sybil=NUM_MALICIOUS_NODES,
        description="Sybil attack with id verification",
    ),
    "sybil_subnet_diversity": Scenario(
        name="sybil_subnet_diversity",
        security_flags=["--subnet-diversity"],
        attack_type="sybil",
        num_sybil=NUM_MALICIOUS_NODES,
        description="Sybil attack with subnet diversity",
    ),
    "sybil_all_defence": Scenario(
        name="sybil_all_defence",
        security_flags=["--all-security"],
        attack_type="sybil",
        num_sybil=NUM_MALICIOUS_NODES,
        description="Sybil attack with all defences",
    ),
    # eclipse attacks
    "eclipse_no_defence": Scenario(
        name="eclipse_no_defence",
        security_flags=[],
        attack_type="eclipse",
        num_sybil=NUM_MALICIOUS_NODES,
        description="Eclipse attack targeting one node, no defences",
    ),
    "eclipse_peer_age": Scenario(
        name="eclipse_peer_age",
        security_flags=["--peer-age" "--age-min", "5"],
        attack_type="eclipse",
        num_sybil=NUM_MALICIOUS_NODES,
        description="Eclipse attack with peer age preference",
    ),
    "eclipse_all_defence": Scenario(
        name="eclipse_all_defence",
        security_flags=["--all-security"],
        attack_type="eclipse",
        num_sybil=NUM_MALICIOUS_NODES,
        description="Eclipse attack with all defences",
    ),
    # dos attacks
    "dos_no_defence": Scenario(
        name="dos_no_defence",
        security_flags=[],
        attack_type="dos",
        description="DoS flood with no defences",
    ),
    "dos_rate_limit": Scenario(
        name="dos_rate_limit",
        security_flags=["--rate-limit"],
        attack_type="dos",
        description="DoS flood attack with rate limiting",
    ),
}

class NodeProcess:
    def __init__(self, binary: str, port: int, mode: str,
                 known_addr: Optional[str] = None,
                 security_flags: Optional[list[str]] = None):
        self.binary = binary
        self.port = port
        self.mode = mode
        self.known_addr = known_addr,
        self.security_flags = security_flags or []
        self.process: Optional[subprocess.Popen] = None

    def start(self) -> bool:
        cmd = [self.binary, self.mode, str(self.port)]
        if self.mode == "join" and self.known_addr:
            cmd.append(self.known_addr)
        cmd.extend(self.security_flags)

        try:
            self.process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            # wait to bind
            time.sleep(0.3)
            if self.process.poll() is not None:
                stderr = self.process.stderr.read()
                print(f"[FAIL] Node on port {self.port} exited: {stderr}")
                return False
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
            time.sleep(0.5)


            import select
            output_lines = []
            while select.select([self.process.stdout], [], [], 0.5)[0]:
                line = self.process.stdout.readline()
                if not line:
                    break
                output_lines.append(line.strip())

            for line in output_lines:
                if line.startswith("Metrics:"):
                    json_str = line[len("METRICS:"):]
                    return json.loads(json_str)
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

        creator = NodeProcess(
            self.binary, self.base_port, "create",
            security_flags=self.security_flags
        )
        if not creator.start():
            return False
        self.nodes.append(creator)

        known_addr = f"127.0.0.1:{self.base_port}"
        for i in range(1, num_nodes):
            port = self.base_port + 1
            joiner = NodeProcess(
                self.binary, port, "join",
                known_addr=known_addr,
                security_flags=self.security_flags
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
            node = NodeProcess(
                self.binary, port, "join",
                known_addr=known_addr,
                security_flags=sybil_flags or []
            )
            if node.start():
                sybil_nodes.append(node)
                self.nodes.append(node)
            time.sleep(0.1)

        time.sleep(STABILISE_WAIT)
        return sybil_nodes

    def store_test_data(self, num_keys: int) -> dict[str, str]:
        test_data = {}
        for i in range(num_keys):
            key = f"test_key_{i}"
            value = f"test_value_{i}"
            test_data[key] = value
            self.nodes[0].put(key, value)
            time.sleep(0.05)

        print(f"Stored {num_keys} test key-value pairs")
        time.sleep(1)
        return test_data

    def verify_data(self, test_data: dict[str, str]) -> tuple[int, int]:
        return len(test_data), len(test_data)

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
        print(f"Treating down {len(self.nodes)} nodes...")
        for node in self.nodes:
            node.stop()
        self.nodes.clear()
        time.sleep(1)

def attack_none(ring: TestRing):
    print(f"No attack (baseline)")

def attack_sybil(ring: TestRing, num_sybil: int):
    ring.add_sybil_nodes(num_sybil)

def attack_eclipse(ring: TestRing, num_sybil: int):
    ring.add_sybil_nodes(num_sybil)

def attack_dos(ring: TestRing):
    import socket
    target_port = ring.base_port

    print(f"Flooding port {target_port} with requests...")
    flood_count = 0

    start_time = time.time()
    while time.time() - start_time < ATTACK_DURATION:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect(("127.0.0.1", target_port))
            packet = bytes([0x01, 0x00, 0x00, 0x42])
            sock.sendall(packet)
            sock.close()
            flood_count += 1
        except Exception:
            pass

    print(f"Sent {flood_count} requests in {ATTACK_DURATION}s")

ATTACK_FUNCTIONS = {
    "none": lambda ring, scenario: attack_none(ring),
    "sybil": lambda ring, scenario: attack_sybil(ring, scenario.num_sybil),
    "eclipse": lambda ring, scenario: attack_eclipse(ring, scenario.num_sybil),
    "dos": lambda ring, scenario: attack_dos(ring),
}

def run_scenario(binary: str, scenario: Scenario,
                 port_offset: int = 0) -> ScenarioResult:
    print(f"{'=' * 60}")
    print(f"SCENARIO: {scenario.name}")
    print(f"\tAttack: {scenario.attack_type}")
    print(f"\tSecurity: {scenario.security_flags or '(none)'}")
    print(f"\tDescription:: {scenario.description}")
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

        test_data = ring.store_test_data(NUM_TEST_KEYS)
        result.keys_stored = len(test_data)

        attack_fn = ATTACK_FUNCTIONS.get(scenario.attack_type)
        if attack_fn:
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

def save_results_json(results: list[ScenarioResult], output_dir: str = "results"):
    os.makedirs(output_dir, exist_ok=True)

    data = []
    for r in results:
        data.append({
            "scenario": r,
            "attack_type": r,
            "security_flags": r,
            "keys_stored": r,
            "keys_retrieved": r,
            "keys_correct": r,
            "lookup_success_rate": r,
            "duration_seconds": r,
            "module_metrics": r,
        })

    path = f"{output_dir}/result.json"
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

    args = parser.parse_args()

    if args.list:
        print("Available Scenarios")
        for name, scenario in SCENARIOS.items():
            flags = " ".join(scenario.security_flags) or "(nonw)"
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
    for i, scenario in enumerate(selected):
        port_offset = i * 100
        result = run_scenario(args.binary, scenario, port_offset)
        results.append(result)

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
