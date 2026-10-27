"""
Manage nftables tables. Each table is owned and replaced as a whole, atomically.
"""

from __future__ import annotations

import hashlib
import ipaddress
import posixpath
import re
from io import StringIO
from collections.abc import Iterator
from typing import Any

from typing_extensions import TypedDict

from pyinfra import host
from pyinfra.api import FileUploadCommand, QuoteString, StringCommand, operation
from pyinfra.api.exceptions import OperationValueError
from pyinfra.facts.files import File, Sha256File
from pyinfra.facts.nftables import (
    NFTABLES_IDENTIFIER_REGEX,
    NftablesTable,
    validate_nftables_table,
)
from pyinfra.operations import files


class RuleSpec(TypedDict, total=False):
    """
    A structured nftables rule. Every key is optional; see ``nftables.table``.
    """

    in_interface: str | list[str]
    out_interface: str | list[str]
    source: str | list[str]
    destination: str | list[str]
    protocol: str
    source_port: int | list[int]
    destination_port: int | list[int]
    ct_state: str | list[str]
    not_in_interface: str | list[str]
    not_out_interface: str | list[str]
    not_source: str | list[str]
    not_destination: str | list[str]
    not_source_port: int | list[int]
    not_destination_port: int | list[int]
    counter: bool
    log_prefix: str
    action: str
    jump: str


Rule = str | RuleSpec


class ChainSpec(TypedDict, total=False):
    """
    An nftables chain. A chain with a ``hook`` is a base chain; see ``nftables.table``.
    """

    hook: str
    type: str
    priority: int | str
    policy: str
    rules: list[Rule]


MARKER_PREFIX = "pyinfra:"

IP_HOOKS = ("prerouting", "input", "forward", "output", "postrouting")
FAMILY_HOOKS: dict[str, tuple[str, ...]] = {
    "ip": IP_HOOKS,
    "ip6": IP_HOOKS,
    "inet": IP_HOOKS,
    "arp": ("input", "output"),
    "bridge": IP_HOOKS,
}

IP_CHAIN_TYPE_HOOKS: dict[str, tuple[str, ...]] = {
    "filter": IP_HOOKS,
    "nat": ("prerouting", "input", "output", "postrouting"),
    "route": ("output",),
}
FAMILY_CHAIN_TYPE_HOOKS: dict[str, dict[str, tuple[str, ...]]] = {
    "ip": IP_CHAIN_TYPE_HOOKS,
    "ip6": IP_CHAIN_TYPE_HOOKS,
    "inet": IP_CHAIN_TYPE_HOOKS,
    "arp": {"filter": FAMILY_HOOKS["arp"]},
    "bridge": {"filter": IP_HOOKS},
}

# Named priorities, as (value, hooks the name is valid for), following nft's compatibility
# matrix. They are rendered as integers, which is also how nft reports them in JSON.
IP_PRIORITIES: dict[str, tuple[int, tuple[str, ...]]] = {
    "raw": (-300, IP_HOOKS),
    "mangle": (-150, IP_HOOKS),
    "dstnat": (-100, ("prerouting",)),
    "filter": (0, IP_HOOKS),
    "security": (50, IP_HOOKS),
    "srcnat": (100, ("postrouting",)),
}
FAMILY_PRIORITIES: dict[str, dict[str, tuple[int, tuple[str, ...]]]] = {
    "ip": IP_PRIORITIES,
    "ip6": IP_PRIORITIES,
    "inet": IP_PRIORITIES,
    "arp": {"filter": (0, FAMILY_HOOKS["arp"])},
    "bridge": {
        "dstnat": (-300, ("prerouting",)),
        "filter": (-200, IP_HOOKS),
        "out": (100, ("output",)),
        "srcnat": (300, ("postrouting",)),
    },
}
PRIORITY_REGEX = re.compile(r"^\s*([a-z]+)\s*(?:([+-])\s*(\d+))?\s*$")
INT32_MIN, INT32_MAX = -(2**31), 2**31 - 1
NAT_PRIORITY_MIN = -200

POLICIES = ("accept", "drop")
ACTIONS = ("accept", "drop", "return")
PROTOCOLS = ("tcp", "udp", "icmp", "ipv6-icmp")
PROTOCOL_FAMILIES = {"icmp": 4, "ipv6-icmp": 6}
CT_STATES = ("new", "established", "related", "invalid", "untracked")
INTERFACE_REGEX = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")
LOG_PREFIX_MAX_BYTES = 63

MATCH_KEYS = (
    "in_interface",
    "out_interface",
    "source",
    "destination",
    "source_port",
    "destination_port",
)
RULE_KEYS = frozenset(
    (*MATCH_KEYS, *(f"not_{key}" for key in MATCH_KEYS))
    + ("protocol", "ct_state", "counter", "log_prefix", "action", "jump")
)

RAW_RULE_LEADING_KEYWORDS = frozenset(
    (
        "type",
        "policy",
        "devices",
        "include",
        "define",
        "table",
        "chain",
        "set",
        "map",
        "flowtable",
        "add",
        "delete",
        "flush",
    )
)
RAW_RULE_FORBIDDEN_CHARS = {
    ";": "';'",
    "#": "'#'",
    "\\": "a backslash",
    "$": "a '$' variable",
}
BRACKETS = {"{": "}", "[": "]"}


def _check_raw_rule(rule: str, where: str) -> None:
    """
    Check that a raw rule is exactly one nft rule fragment. nft strings have no escapes, so a
    double quote always starts or ends a string.
    """

    if not rule.strip():
        raise OperationValueError(f"{where}: rule is empty")

    outside: list[str] = []
    stack: list[str] = []
    in_string = False
    for char in rule:
        if char in "\r\n":
            raise OperationValueError(f"{where}: rule contains a newline")
        if char == '"':
            in_string = not in_string
            outside.append(" ")
            continue
        if in_string:
            continue
        if char in RAW_RULE_FORBIDDEN_CHARS:
            raise OperationValueError(
                f"{where}: rule contains {RAW_RULE_FORBIDDEN_CHARS[char]} outside a quoted string",
            )
        if char in BRACKETS:
            stack.append(BRACKETS[char])
        elif char in BRACKETS.values():
            if not stack or stack.pop() != char:
                raise OperationValueError(f"{where}: rule has unbalanced brackets")
        outside.append(char)

    if in_string:
        raise OperationValueError(f"{where}: rule has an unterminated quoted string")
    if stack:
        raise OperationValueError(f"{where}: rule has unbalanced brackets")

    words = re.findall(r"[A-Za-z_][A-Za-z0-9_-]*", "".join(outside))
    if words and words[0] in RAW_RULE_LEADING_KEYWORDS:
        raise OperationValueError(f"{where}: rule can't start with {words[0]!r}")
    if "comment" in words:
        raise OperationValueError(
            f"{where}: rule can't set a comment (pyinfra uses it to track the rule)",
        )


def _many(spec: dict[str, Any], key: str, where: str) -> list[Any]:
    value = spec[key]
    values = value if isinstance(value, list) else [value]
    if not values:
        raise OperationValueError(f"{where}.{key}: list must not be empty")
    return values


def _format_values(values: list[str]) -> str:
    if len(values) == 1:
        return values[0]
    return "{ " + ", ".join(values) + " }"


def _interfaces(spec: dict[str, Any], key: str, where: str) -> str:
    names = _many(spec, key, where)
    for name in names:
        if not isinstance(name, str) or not INTERFACE_REGEX.fullmatch(name):
            raise OperationValueError(f"{where}.{key}: invalid interface name {name!r}")
    return _format_values([f'"{name}"' for name in sorted(set(names))])


def _addresses(spec: dict[str, Any], key: str, where: str) -> tuple[int, str]:
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for value in _many(spec, key, where):
        if not isinstance(value, str) or "%" in value:
            raise OperationValueError(f"{where}.{key}: invalid address {value!r}")
        try:
            networks.append(ipaddress.ip_network(value))
        except ValueError as e:
            raise OperationValueError(f"{where}.{key}: invalid address {value!r} ({e})") from e

    versions = {network.version for network in networks}
    if len(versions) != 1:
        raise OperationValueError(f"{where}.{key}: can't mix IPv4 and IPv6 addresses")

    # Collapse overlapping networks: nft merges or rejects overlapping set intervals
    collapsed = ipaddress.collapse_addresses(networks)  # type: ignore[type-var]
    rendered = [
        str(network.network_address) if network.prefixlen == network.max_prefixlen else str(network)
        for network in collapsed
    ]
    return versions.pop(), _format_values(rendered)


def _ports(spec: dict[str, Any], key: str, where: str) -> str:
    ports = _many(spec, key, where)
    for port in ports:
        if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
            raise OperationValueError(f"{where}.{key}: invalid port {port!r}")
    return _format_values([str(port) for port in sorted(set(ports))])


def _render_structured_rule(
    family: str,
    spec: dict[str, Any],
    regular_chains: set[str],
    where: str,
) -> str:
    if family not in ("ip", "ip6", "inet"):
        raise OperationValueError(
            f"{where}: structured rules are only supported in ip, ip6 and inet tables; "
            "use a raw rule string",
        )

    unknown = sorted(set(spec) - RULE_KEYS)
    if unknown:
        raise OperationValueError(f"{where}: unknown rule keys: {', '.join(unknown)}")
    for key, value in spec.items():
        if value is None:
            raise OperationValueError(f"{where}.{key}: must not be None")
    for key in MATCH_KEYS:
        if key in spec and f"not_{key}" in spec:
            raise OperationValueError(f"{where}: can't set both {key} and not_{key}")

    parts: list[str] = []

    for key, keyword in (("in_interface", "iifname"), ("out_interface", "oifname")):
        for negate in (False, True):
            name = f"not_{key}" if negate else key
            if name in spec:
                op = "!= " if negate else ""
                parts.append(f"{keyword} {op}{_interfaces(spec, name, where)}")

    address_version: int | None = None
    for key, field in (("source", "saddr"), ("destination", "daddr")):
        for negate in (False, True):
            name = f"not_{key}" if negate else key
            if name not in spec:
                continue
            version, rendered = _addresses(spec, name, where)
            if address_version is not None and version != address_version:
                raise OperationValueError(f"{where}: can't mix IPv4 and IPv6 addresses")
            address_version = version
            op = "!= " if negate else ""
            parts.append(f"{'ip' if version == 4 else 'ip6'} {field} {op}{rendered}")

    protocol = spec.get("protocol")
    if protocol is not None and protocol not in PROTOCOLS:
        raise OperationValueError(
            f"{where}.protocol: invalid protocol {protocol!r} "
            f"(expected one of {', '.join(PROTOCOLS)})",
        )

    rule_version = PROTOCOL_FAMILIES.get(protocol) if protocol is not None else None
    if rule_version is not None and address_version not in (None, rule_version):
        raise OperationValueError(
            f"{where}: protocol {protocol} doesn't match the addresses' IP version",
        )
    rule_version = rule_version or address_version
    table_version = {"ip": 4, "ip6": 6}.get(family)
    if table_version is not None and rule_version not in (None, table_version):
        raise OperationValueError(f"{where}: rule doesn't match the {family} table's IP version")

    port_parts: list[str] = []
    for key, field in (("source_port", "sport"), ("destination_port", "dport")):
        for negate in (False, True):
            name = f"not_{key}" if negate else key
            if name not in spec:
                continue
            if protocol not in ("tcp", "udp"):
                raise OperationValueError(f"{where}.{name}: ports need protocol tcp or udp")
            op = "!= " if negate else ""
            port_parts.append(f"{protocol} {field} {op}{_ports(spec, name, where)}")

    if protocol is not None and not port_parts:
        parts.append(f"meta l4proto {protocol}")
    parts.extend(port_parts)

    if "ct_state" in spec:
        states = _many(spec, "ct_state", where)
        for state in states:
            if state not in CT_STATES:
                raise OperationValueError(f"{where}.ct_state: invalid state {state!r}")
        parts.append(f"ct state {','.join(s for s in CT_STATES if s in states)}")

    has_effect = False

    counter = spec.get("counter", False)
    if not isinstance(counter, bool):
        raise OperationValueError(f"{where}.counter: must be a bool")
    if counter:
        parts.append("counter")
        has_effect = True

    if "log_prefix" in spec:
        prefix = spec["log_prefix"]
        if (
            not isinstance(prefix, str)
            or not prefix
            or '"' in prefix
            or any(ord(char) < 32 or ord(char) == 127 for char in prefix)
        ):
            raise OperationValueError(
                f"{where}.log_prefix: must be a non-empty string without double quotes or "
                "control characters",
            )
        if len(prefix.encode()) > LOG_PREFIX_MAX_BYTES:
            raise OperationValueError(
                f"{where}.log_prefix: must be at most {LOG_PREFIX_MAX_BYTES} bytes",
            )
        parts.append(f'log prefix "{prefix}"')
        has_effect = True

    if "action" in spec and "jump" in spec:
        raise OperationValueError(f"{where}: can't set both action and jump")
    if "action" in spec:
        if spec["action"] not in ACTIONS:
            raise OperationValueError(
                f"{where}.action: invalid action {spec['action']!r} "
                f"(expected one of {', '.join(ACTIONS)})",
            )
        parts.append(spec["action"])
        has_effect = True
    if "jump" in spec:
        if spec["jump"] not in regular_chains:
            raise OperationValueError(
                f"{where}.jump: {spec['jump']!r} isn't a regular chain in this table",
            )
        parts.append(f"jump {spec['jump']}")
        has_effect = True

    if not has_effect:
        raise OperationValueError(f"{where}: rule needs an action, jump, counter or log_prefix")

    return " ".join(parts)


def _marker(rule: str) -> str:
    return MARKER_PREFIX + hashlib.sha256(rule.encode()).hexdigest()[:16]


def _parse_priority(family: str, hook: str, priority: Any, where: str) -> int:
    if isinstance(priority, int) and not isinstance(priority, bool):
        value = priority
    elif isinstance(priority, str):
        match = PRIORITY_REGEX.match(priority)
        if not match:
            raise OperationValueError(f"{where}.priority: invalid priority {priority!r}")
        name, sign, offset = match.groups()
        names = FAMILY_PRIORITIES[family]
        if name not in names:
            raise OperationValueError(
                f"{where}.priority: unknown priority name {name!r} for the {family} family",
            )
        value, hooks = names[name]
        if hook not in hooks:
            raise OperationValueError(
                f"{where}.priority: {name!r} can't be used with the {hook} hook",
            )
        if offset is not None:
            value += int(offset) if sign == "+" else -int(offset)
    else:
        raise OperationValueError(f"{where}.priority: must be an int or a string")

    if not INT32_MIN <= value <= INT32_MAX:
        raise OperationValueError(f"{where}.priority: out of range")
    return value


def _check_jump_cycles(jumps: dict[str, set[str]]) -> None:
    visiting: set[str] = set()
    done: set[str] = set()

    def visit(chain: str, path: list[str]) -> None:
        if chain in done:
            return
        if chain in visiting:
            cycle = " -> ".join(path[path.index(chain) :] + [chain])
            raise OperationValueError(f"jump cycle between chains: {cycle}")
        visiting.add(chain)
        for target in sorted(jumps.get(chain, ())):
            visit(target, path + [chain])
        visiting.discard(chain)
        done.add(chain)

    for chain in sorted(jumps):
        visit(chain, [])


def _build_chains(
    family: str,
    chains: dict[str, ChainSpec],
) -> dict[str, dict[str, Any]]:
    """
    Validate the chain specs and return each chain's desired state: its base chain settings,
    if any, and the rendered text of each rule (without its marker).
    """

    if not isinstance(chains, dict):
        raise OperationValueError("chains must be a dict of chain name to chain spec")

    regular_chains = {
        name for name, spec in chains.items() if isinstance(spec, dict) and "hook" not in spec
    }
    desired: dict[str, dict[str, Any]] = {}
    jumps: dict[str, set[str]] = {}

    for name in sorted(chains):
        spec: dict[str, Any] = chains[name]  # type: ignore[assignment]
        where = f"chains[{name!r}]"
        if not isinstance(name, str) or not NFTABLES_IDENTIFIER_REGEX.fullmatch(name):
            raise OperationValueError(f"invalid nftables chain name: {name!r}")
        if not isinstance(spec, dict):
            raise OperationValueError(f"{where}: must be a dict")

        unknown = sorted(set(spec) - {"hook", "type", "priority", "policy", "rules"})
        if unknown:
            raise OperationValueError(f"{where}: unknown chain keys: {', '.join(unknown)}")

        chain: dict[str, Any] = {}
        if "hook" in spec:
            hook = spec["hook"]
            if hook not in FAMILY_HOOKS[family]:
                raise OperationValueError(
                    f"{where}.hook: invalid hook {hook!r} for the {family} family "
                    f"(expected one of {', '.join(FAMILY_HOOKS[family])})",
                )
            chain_type = spec.get("type", "filter")
            type_hooks = FAMILY_CHAIN_TYPE_HOOKS[family]
            if chain_type not in type_hooks:
                raise OperationValueError(
                    f"{where}.type: invalid chain type {chain_type!r} for the {family} family",
                )
            if hook not in type_hooks[chain_type]:
                raise OperationValueError(
                    f"{where}: a {chain_type} chain can't use the {hook} hook",
                )
            if "priority" not in spec:
                raise OperationValueError(f"{where}: a base chain needs a priority")
            policy = spec.get("policy", "accept")
            if policy not in POLICIES:
                raise OperationValueError(
                    f"{where}.policy: invalid policy {policy!r} (expected accept or drop)",
                )
            prio = _parse_priority(family, hook, spec["priority"], where)
            # conntrack hooks in at -200, which NAT needs to come after
            if chain_type == "nat" and prio <= NAT_PRIORITY_MIN:
                raise OperationValueError(
                    f"{where}.priority: a nat chain's priority must be above {NAT_PRIORITY_MIN}",
                )
            chain.update(type=chain_type, hook=hook, prio=prio, policy=policy)
        else:
            present_base_keys = sorted({"type", "priority", "policy"} & set(spec))
            if present_base_keys:
                raise OperationValueError(
                    f"{where}: {', '.join(present_base_keys)} need a hook (a chain without a "
                    "hook is a regular chain)",
                )

        rules = spec.get("rules", [])
        if not isinstance(rules, list):
            raise OperationValueError(f"{where}.rules: must be a list")

        rendered: list[str] = []
        for index, rule in enumerate(rules):
            rule_where = f"{where}.rules[{index}]"
            if isinstance(rule, str):
                _check_raw_rule(rule, rule_where)
                rendered.append(rule.strip())
            elif isinstance(rule, dict):
                rendered.append(
                    _render_structured_rule(family, rule, regular_chains, rule_where),
                )
                if "jump" in rule:
                    jumps.setdefault(name, set()).add(rule["jump"])
            else:
                raise OperationValueError(f"{rule_where}: must be a string or a dict")

        chain["rules"] = rendered
        desired[name] = chain

    _check_jump_cycles(jumps)
    return desired


def _render_table(family: str, table: str, chains: dict[str, dict[str, Any]]) -> str:
    lines = [
        f"table {family} {table}",
        f"delete table {family} {table}",
        f"table {family} {table} {{",
    ]
    for name, chain in chains.items():
        lines.append(f"    chain {name} {{")
        if "hook" in chain:
            lines.append(
                f"        type {chain['type']} hook {chain['hook']} priority {chain['prio']}; "
                f"policy {chain['policy']};",
            )
        for rule in chain["rules"]:
            lines.append(f'        {rule} comment "{_marker(rule)}"')
        lines.append("    }")
    lines.append("}")
    return "\n".join(lines) + "\n"


def _expected_fact(chains: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """
    Return the ``NftablesTable`` fact value of a live table that matches ``chains``.
    """

    return {
        "flags": [],
        "objects": [],
        "chains": {
            name: {
                **{key: value for key, value in chain.items() if key != "rules"},
                "rules": [_marker(rule) for rule in chain["rules"]],
            }
            for name, chain in chains.items()
        },
    }


def _validate_path(path: str) -> None:
    if (
        not path.startswith("/")
        or path.endswith("/")
        or posixpath.basename(path).startswith("-")
        or "\n" in path
    ):
        raise OperationValueError(
            f"path must be an absolute file path without a trailing slash: {path!r}",
        )


@operation()
def table(
    table: str,
    family: str = "inet",
    chains: dict[str, ChainSpec] | None = None,
    present: bool = True,
    path: str | None = None,
):
    """
    Manage an nftables table. The operation owns the whole table: it replaces it
    atomically, in a single ``nft -f`` transaction, whenever the live table differs from
    the desired one. Other tables (ufw, Docker, Tailscale, ...) are never touched.

    + table: name of the table
    + family: table family, one of ``ip``, ``ip6``, ``inet``, ``arp`` or ``bridge``
    + chains: dict of chain name to chain spec (see below)
    + present: whether the table should exist
    + path: optional absolute file path to also save the rendered table to

    **Chains:**

    Each chain spec is a dict. A chain with a ``hook`` is a base chain, and takes a
    ``priority`` (an integer, or a name such as ``filter`` or ``"filter - 10"``), an
    optional ``type`` (``filter``, ``nat`` or ``route``; defaults to ``filter``) and an
    optional ``policy`` (``accept`` or ``drop``; defaults to ``accept``). A chain without
    a ``hook`` is a regular chain, which rules can ``jump`` to. ``rules`` is the ordered
    list of the chain's rules.

    **Rules:**

    Each rule is either a raw nft rule string, such as ``"tcp dport 22 accept"``, or a
    dict. A dict can match on ``in_interface``, ``out_interface``, ``source``,
    ``destination``, ``protocol`` (``tcp``, ``udp``, ``icmp`` or ``ipv6-icmp``),
    ``source_port``, ``destination_port`` (both need ``protocol`` ``tcp`` or ``udp``) and
    ``ct_state``, and negate the interface, address and port keys with a ``not_`` prefix
    (e.g. ``not_source``). Its effects are ``counter`` (bool), ``log_prefix``, and either
    ``action`` (``accept``, ``drop`` or ``return``) or ``jump`` (a regular chain). A list
    value matches any of its items; separate keys must all match. In an ``inet`` table,
    an address restricts the rule to that address's IP version. Use raw rules for
    anything else (NAT, port ranges, ICMP types, ...).

    **Drift detection:**

    pyinfra stores a short hash of each rule in the rule's comment (so rules can't set
    their own comment). The table is re-applied when it's missing, has any flags (such
    as ``dormant``) or named objects (such as sets), or when its chains, chain settings,
    or ordered rule markers differ.
    This catches rules that were added, removed, reordered or replaced by hand
    (``nft replace rule`` drops the comment), but not an edit that keeps the comment.
    Re-applying resets the table's counters.

    **Persistence:**

    ``path`` is written only after the table loads successfully, is always replaced
    atomically, and is repaired without reloading if the live table is already up to date. Loading it at boot is
    up to you, for example with a oneshot systemd unit that runs ``nft -f path``. Note
    that the distro ``nftables.service`` typically runs ``flush ruleset``, which removes
    every table.

    **Notes:**

    An accept in this table doesn't override a drop in another table on the same hook.
    Requires a JSON-capable ``nft`` (1.0.2 or later), GNU coreutils, and ``_sudo=True``.
    Sets, maps, the ``netdev`` family and ingress/egress hooks aren't supported. Table and
    chain names that are nft keywords (such as ``ip`` or ``table``) are rejected by nft.

    **Example:**

    .. code:: python

        nftables.table(
            name="Only allow SSH over tailscale",
            table="ssh_filter",
            chains={
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
            },
            path="/etc/nftables.d/ssh_filter.nft",
            _sudo=True,
        )

        nftables.table(
            name="Masquerade the lab subnet",
            table="lab_nat",
            family="ip",
            chains={
                "postrouting": {
                    "type": "nat",
                    "hook": "postrouting",
                    "priority": "srcnat",
                    "rules": ['ip saddr 192.168.50.0/24 oifname "eth0" masquerade'],
                },
            },
            _sudo=True,
        )
    """

    try:
        validate_nftables_table(family, table)
    except ValueError as e:
        raise OperationValueError(str(e)) from e
    if path is not None:
        _validate_path(path)

    live = host.get_fact(NftablesTable, family=family, table=table)

    if not present:
        commands = []
        if live is not None:
            commands.append(
                StringCommand("nft delete table", QuoteString(family), QuoteString(table))
            )
        if path is not None:
            commands.extend(files.file._inner(path=path, present=False))
        if not commands:
            host.noop(f"nftables table {family} {table} does not exist")
            return
        yield from commands
        return

    if chains is None:
        chains = {}
    desired = _build_chains(family, chains)
    rendered = _render_table(family, table, desired)

    digest = hashlib.sha256(rendered.encode()).hexdigest()
    load = live != _expected_fact(desired)

    if not load:
        if path is None or _path_in_sync(path, digest):
            host.noop(f"nftables table {family} {table} is up to date")
            return

    yield from _apply(rendered, digest, path, load)


def _path_in_sync(path: str, digest: str) -> bool:
    file_info = host.get_fact(File, path=path)
    if not isinstance(file_info, dict) or file_info.get("mode") != 644:
        return False
    return host.get_fact(Sha256File, path=path) == digest


def _apply(
    rendered: str, digest: str, path: str | None, load: bool
) -> Iterator[FileUploadCommand | StringCommand]:
    """
    Upload the rendered table, then load it and/or save it to ``path``. Only a byte-exact
    upload is used, ``path`` is written only after a successful load and is replaced
    atomically, and cleanup keeps the first failure's exit status.
    """

    temp_dir = None
    if host.current_op_global_arguments:
        temp_dir = host.current_op_global_arguments.get("_temp_dir")

    temp_filename = host.get_temp_filename(digest, temp_directory=temp_dir)

    yield FileUploadCommand(
        StringIO(rendered),
        temp_filename,
        remote_temp_filename=host.get_temp_filename(f"{digest}-upload", temp_directory=temp_dir),
    )

    steps: list[Any] = [
        '[ "$(sha256sum <',
        QuoteString(temp_filename),
        "| cut -d' ' -f1)\" =",
        QuoteString(digest),
        "]",
    ]
    if load:
        steps += ["&& nft -f", QuoteString(temp_filename)]
    cleanup = ["; rc=$?; rm -f --", QuoteString(temp_filename)]

    if path is None:
        yield StringCommand(*steps, *cleanup, "; exit $rc")
        return

    directory = posixpath.dirname(path)
    staging = posixpath.join(directory, f".{posixpath.basename(path)}.XXXXXX")
    yield StringCommand(
        "new=; [ ! -d",
        QuoteString(path),
        "] && mkdir -p --",
        QuoteString(directory),
        "&&",
        *steps,
        "&& new=$(mktemp --",
        QuoteString(staging),
        ") && install -T -m 0644 --",
        QuoteString(temp_filename),
        '"$new" && mv -f -T -- "$new"',
        QuoteString(path),
        *cleanup,
        '; [ -z "$new" ] || rm -f -- "$new"; exit $rc',
    )
