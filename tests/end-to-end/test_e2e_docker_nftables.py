"""
Docker based nftables tests, run against the real ``nft`` of each Ubuntu image.

The chain and priority matrix comes from the "Supported chain types" and "Standard priority
names" tables of nft(8), which are the same for nftables 1.0.2 (Ubuntu 22.04) and 1.1.6
(Ubuntu 26.04). Containers share the host's kernel, so these tests cover nft userspace
versions, not kernel versions.
"""

from __future__ import annotations

import itertools
import json
import shlex
import tempfile
from pathlib import Path

import pytest

from pyinfra.api.exceptions import OperationValueError
from pyinfra.facts.nftables import NftablesTable
from pyinfra.operations.nftables import _build_chains, _render_table

IMAGES = ["ubuntu:22.04", "ubuntu:26.04"]

FAMILIES = ["ip", "ip6", "inet", "arp", "bridge"]
HOOKS = ["prerouting", "input", "forward", "output", "postrouting", "ingress", "egress"]
CHAIN_TYPES = ["filter", "nat", "route"]
PRIORITIES: list[int | str] = [
    0,
    -10,
    -199,
    -200,
    -300,
    100,
    "raw",
    "mangle",
    "dstnat",
    "filter",
    "security",
    "srcnat",
    "out",
    "filter - 10",
    "dstnat + 5",
]


# Combinations newer nft accepts but nftables.table deliberately rejects. nft 1.0.2 rejects
# all of these too, so the stricter rule is the one that works on every supported version.
def _stricter_than_nft(family: str, hook: str, chain_type: str, priority: int | str) -> bool:
    # ingress needs devices, which v1 doesn't support (nft -c doesn't check the device)
    if family == "inet" and hook == "ingress":
        return True
    # nft(8) lists dstnat for prerouting and srcnat for postrouting only; nft 1.1 also
    # resolves them on the output and input hooks
    name = str(priority).split()[0]
    return (name, hook) in {("dstnat", "output"), ("srcnat", "input")}


# Structured rules for each table family. Every one must render and load.
STRUCTURED_RULES: dict[str, list[dict]] = {
    "inet": [
        {"in_interface": "eth0", "action": "accept"},
        {"in_interface": ["eth0", "eth1"], "out_interface": "eth2", "action": "accept"},
        {"not_in_interface": "lo", "not_out_interface": ["eth0", "eth1"], "action": "drop"},
        {"source": "10.0.0.0/8", "action": "accept"},
        {"source": ["10.0.0.0/8", "192.168.0.0/16", "10.1.0.0/16"], "action": "accept"},
        {"destination": "2001:db8::/32", "action": "accept"},
        {"not_source": "192.0.2.0/24", "not_destination": "198.51.100.1", "action": "drop"},
        {"protocol": "tcp", "action": "accept"},
        {"protocol": "udp", "source_port": 53, "action": "accept"},
        {"protocol": "tcp", "destination_port": [22, 80, 443], "action": "accept"},
        {"protocol": "udp", "not_destination_port": [53, 5353], "action": "drop"},
        {"protocol": "tcp", "not_source_port": 1, "destination_port": 22, "action": "accept"},
        {"protocol": "icmp", "action": "accept"},
        {"protocol": "ipv6-icmp", "action": "accept"},
        {"protocol": "icmp", "source": "10.0.0.1", "action": "accept"},
        {"ct_state": "established", "action": "accept"},
        {"ct_state": ["new", "established", "related", "invalid", "untracked"], "action": "accept"},
        {"counter": True},
        {"log_prefix": "x"},
        {"log_prefix": "with; semicolon # hash \\ backslash", "counter": True, "action": "drop"},
        {"action": "return"},
        {"jump": "next"},
        {
            "in_interface": "tailscale0",
            "source": "100.64.0.0/10",
            "protocol": "tcp",
            "destination_port": 22,
            "ct_state": "new",
            "counter": True,
            "log_prefix": "ssh ",
            "action": "accept",
        },
    ],
    "ip": [
        {"source": "10.0.0.0/8", "protocol": "tcp", "destination_port": 22, "action": "accept"},
        {"protocol": "icmp", "action": "accept"},
    ],
    "ip6": [
        {"source": "fd00::/8", "protocol": "udp", "destination_port": 546, "action": "accept"},
        {"protocol": "ipv6-icmp", "action": "accept"},
    ],
}

# Raw rules taken from nft(8) examples, plus forms the scanner must allow.
RAW_RULES = [
    "tcp dport { 22, 80, 443 } accept",
    "tcp dport 8000-8100 accept",
    "ip saddr 10.0.0.0/8 tcp dport ssh accept",
    "ip6 nexthdr ipv6-icmp icmpv6 type { echo-request, echo-reply } accept",
    "icmp type echo-request limit rate 5/second accept",
    "ct state established,related accept",
    "ct state invalid drop",
    "meta l4proto { tcp, udp } th dport 53 accept",
    'iifname "lo" accept',
    'iifname "eth*" accept',
    "tcp flags syn tcp option maxseg size set rt mtu",
    "tcp dport vmap { 22 : accept, 23 : drop }",
    "ip saddr . tcp dport { 10.0.0.1 . 22, 10.0.0.2 . 80 } accept",
    'log prefix "a;b # c" counter drop',
    "reject with icmpx type admin-prohibited",
    "meta mark set 0x1 counter",
    "jump next",
    "goto next",
]


def _render(family: str, chains: dict) -> str:
    return _render_table(family, "t", _build_chains(family, chains))


def _render_unchecked(family: str, hook: str, chain_type: str, priority: int | str) -> str:
    return (
        f"table {family} t\ndelete table {family} t\ntable {family} t {{\n"
        f"    chain c {{\n        type {chain_type} hook {hook} priority {priority}; "
        "policy accept;\n    }\n}\n"
    )


def _nft_check(helpers, container: str, files: dict[str, str]) -> dict[str, tuple[bool, str]]:
    """
    Run ``nft -c -f`` on each file in the container, returning ``(accepted, stderr)``.
    """

    with tempfile.TemporaryDirectory() as tmp:
        cases = Path(tmp, "cases")
        cases.mkdir()
        for name, content in files.items():
            (cases / f"{name}.nft").write_text(content)
        helpers.run(f"docker exec {container} rm -rf /cases")
        helpers.run(f"docker cp {cases} {container}:/cases")

    script = (
        "for f in /cases/*.nft; do "
        'err=$(nft -c -f "$f" 2>&1); rc=$?; '
        'printf "%s\\t%s\\t%s\\n" "$(basename "$f" .nft)" "$rc" "$(echo "$err" | head -1)"; '
        "done"
    )
    stdout, _ = helpers.run(f"docker exec {container} sh -c {shlex.quote(script)}")
    results = {}
    for line in stdout.splitlines():
        name, rc, err = line.split("\t", 2)
        results[name] = (rc == "0", err)
    return results


@pytest.fixture(scope="module", params=IMAGES)
def nft_container(request, helpers):
    stdout, _ = helpers.run(f"docker run -d --cap-add NET_ADMIN {request.param} tail -f /dev/null")
    container = stdout.strip()
    try:
        helpers.run(
            f"docker exec {container} sh -c 'apt-get update -qq && "
            "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables'",
        )
        yield container
    finally:
        helpers.run(f"docker rm -f {container}")


@pytest.mark.end_to_end
@pytest.mark.end_to_end_docker
def test_int_docker_nftables_chain_matrix(helpers, nft_container):
    """
    Every family, hook, chain type and priority the operation accepts must load in nft, and
    everything it rejects must be rejected by nft too, apart from ``_stricter_than_nft``.
    """

    accepted: dict[str, str] = {}
    rejected: dict[str, str] = {}
    stricter: set[str] = set()
    for family, hook, chain_type, priority in itertools.product(
        FAMILIES, HOOKS, CHAIN_TYPES, PRIORITIES
    ):
        name = f"{family}-{hook}-{chain_type}-{priority}".replace(" ", "")
        spec = {"c": {"hook": hook, "type": chain_type, "priority": priority}}
        try:
            accepted[name] = _render(family, spec)
        except OperationValueError:
            rejected[name] = _render_unchecked(family, hook, chain_type, priority)
            if _stricter_than_nft(family, hook, chain_type, priority):
                stricter.add(name)

    assert accepted and rejected
    results = _nft_check(helpers, nft_container, {**accepted, **rejected})

    not_loaded = {name: results[name][1] for name in accepted if not results[name][0]}
    assert not not_loaded, f"accepted by nftables.table but rejected by nft: {not_loaded}"

    allowed_by_nft = {name for name in rejected if results[name][0]}
    unexpected = sorted(allowed_by_nft - stricter)
    assert not unexpected, f"accepted by nft but rejected by nftables.table: {unexpected}"


@pytest.mark.end_to_end
@pytest.mark.end_to_end_docker
def test_int_docker_nftables_rule_corpus(helpers, nft_container):
    """
    Every structured rule form and every raw rule example must load in nft.
    """

    files = {}
    for family, rules in STRUCTURED_RULES.items():
        for index, rule in enumerate(rules):
            files[f"struct-{family}-{index}"] = _render(
                family,
                {"c": {"hook": "input", "priority": 0, "rules": [rule]}, "next": {}},
            )
    for index, rule in enumerate(RAW_RULES):
        files[f"raw-{index}"] = _render(
            "inet",
            {"c": {"hook": "input", "priority": 0, "rules": [rule]}, "next": {}},
        )
    files["nat-raw"] = _render(
        "ip",
        {
            "pre": {
                "type": "nat",
                "hook": "prerouting",
                "priority": "dstnat",
                "rules": ["tcp dport 8080 dnat to 10.0.0.2:80"],
            },
            "post": {
                "type": "nat",
                "hook": "postrouting",
                "priority": "srcnat",
                "rules": ['oifname "eth0" masquerade'],
            },
        },
    )

    results = _nft_check(helpers, nft_container, files)
    failed = {name: err for name, (ok, err) in results.items() if not ok}
    assert not failed, failed


DEPLOY = """
import json, os
from pyinfra.operations import nftables

spec = json.load(open(os.environ["NFT_TEST_SPEC"]))
nftables.table(name="nftables e2e", _sudo=False, **spec)
"""

SSH_CHAINS = {
    "input": {
        "hook": "input",
        "priority": "filter - 10",
        "rules": [
            {
                "in_interface": "tailscale0",
                "protocol": "tcp",
                "destination_port": 22,
                "action": "accept",
            },
            {"protocol": "tcp", "destination_port": 22, "action": "drop"},
        ],
    },
}
PERSIST_PATH = "/etc/nftables.d/e2e.nft"


@pytest.mark.end_to_end
@pytest.mark.end_to_end_docker
def test_int_docker_nftables_table_lifecycle(helpers, nft_container, tmp_path):
    """
    Apply, re-apply after drift made by hand, repair the saved file, and delete the table.
    """

    deploy = tmp_path / "deploy.py"
    deploy.write_text(DEPLOY)
    spec_file = tmp_path / "spec.json"

    def run(spec: dict, expected: str, expected_exit_code: int = 0) -> None:
        spec_file.write_text(json.dumps(spec))
        helpers.run_check_output(
            f"NFT_TEST_SPEC={spec_file} pyinfra -y @docker/{nft_container} {deploy}",
            expected_lines=[rf"\[@docker/{nft_container}\] {expected}"],
            expected_exit_code=expected_exit_code,
        )

    def sh(command: str, expected_exit_code: int = 0) -> str:
        stdout, _ = helpers.run(
            f"docker exec {nft_container} sh -c {shlex.quote(command)}",
            expected_exit_code=expected_exit_code,
        )
        return stdout

    def handles() -> str:
        return sh("nft -a list table inet e2e")

    helpers.run(f"docker exec {nft_container} nft flush ruleset")
    sh(f"rm -f {PERSIST_PATH}")
    spec = {"table": "e2e", "chains": SSH_CHAINS, "path": PERSIST_PATH}

    run(spec, "Success")
    listing = handles()
    assert 'iifname "tailscale0" tcp dport 22 accept comment "pyinfra:' in listing
    assert sh(f"stat -c %a {PERSIST_PATH}").strip() == "644"
    assert sh("nft -f " + PERSIST_PATH + " && echo reloaded").strip() == "reloaded"
    run(spec, "No changes")

    # Drift made by hand is re-applied, and the next run is a no-op again
    rule_handle = sh(
        "nft -a list chain inet e2e input | sed -n 's/.*tcp dport 22 drop.*# handle //p'"
    ).strip()
    for edit in [
        "nft flush ruleset",
        "nft add rule inet e2e input tcp dport 23 drop",
        f"nft replace rule inet e2e input handle {rule_handle} tcp dport 22 accept",
        "nft add chain inet e2e input '{ policy drop; }'",
        "nft add table inet e2e '{ flags dormant; }'",
        "nft add chain inet e2e extra",
        "nft add set inet e2e allow '{ type ipv4_addr; }'",
    ]:
        sh(edit)
        run(spec, "Success")
        run(spec, "No changes")

    # A changed priority is re-applied through the table replace
    changed = json.loads(json.dumps(spec))
    changed["chains"]["input"]["priority"] = 5
    run(changed, "Success")
    assert "priority filter + 5;" in handles()
    run(spec, "Success")

    # A rule nft rejects fails the operation and changes nothing
    before, saved = handles(), sh(f"cat {PERSIST_PATH}")
    broken = json.loads(json.dumps(spec))
    broken["chains"]["input"]["rules"].append("tcp dport 22 frobnicate")
    for continue_on_error in (False, True):
        run({**broken, "_continue_on_error": continue_on_error}, "Error", expected_exit_code=1)
        assert handles() == before
        assert sh(f"cat {PERSIST_PATH}") == saved
        assert sh("ls /tmp | grep -c pyinfra || true").strip() == "0"

    # The saved file is repaired, atomically and without reloading the table
    for damage in (
        f"rm {PERSIST_PATH}",
        f"echo junk > {PERSIST_PATH}",
        f"chmod 600 {PERSIST_PATH}",
    ):
        sh(damage)
        run(spec, "Success")
        assert handles() == before
        assert sh(f"cat {PERSIST_PATH}") == saved
        assert sh(f"stat -c %a {PERSIST_PATH}").strip() == "644"
        assert sh("ls -A /etc/nftables.d").split() == ["e2e.nft"]
        run(spec, "No changes")

    # A directory at the path fails before the table is touched
    sh("nft flush ruleset")
    sh(f"rm {PERSIST_PATH} && mkdir {PERSIST_PATH}")
    run(spec, "Error", expected_exit_code=1)
    sh("nft list table inet e2e", expected_exit_code=1)
    sh(f"rmdir {PERSIST_PATH}")

    # Removal deletes the table and the saved file, then is a no-op
    run(spec, "Success")
    run({"table": "e2e", "present": False, "path": PERSIST_PATH}, "Success")
    sh("nft list table inet e2e", expected_exit_code=1)
    sh(f"test ! -e {PERSIST_PATH}")
    run({"table": "e2e", "present": False, "path": PERSIST_PATH}, "No changes")

    # Without root the fact fails instead of reporting a missing table
    sh("nft add table inet e2e")
    command = NftablesTable().command("inet", "e2e").get_raw_value()
    helpers.run(
        f"docker exec -u nobody {nft_container} sh -c {shlex.quote(command)}",
        expected_exit_code=1,
    )
