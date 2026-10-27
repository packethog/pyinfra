from __future__ import annotations

import json
import re
from typing import Any

from typing_extensions import override

from pyinfra.api import FactBase, QuoteString, StringCommand
from pyinfra.api.exceptions import FactProcessError

NFTABLES_FAMILIES = ("ip", "ip6", "inet", "arp", "bridge")
NFTABLES_IDENTIFIER_REGEX = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")


def validate_nftables_table(family: str, table: str) -> None:
    """
    Raise ``ValueError`` unless ``family`` and ``table`` are safe to use as nft tokens.
    """

    if family not in NFTABLES_FAMILIES:
        raise ValueError(
            f"invalid nftables family: {family!r} (expected one of {', '.join(NFTABLES_FAMILIES)})"
        )
    if not NFTABLES_IDENTIFIER_REGEX.fullmatch(table):
        raise ValueError(f"invalid nftables table name: {table!r}")


def _require(item: dict[str, Any], key: str, what: str) -> Any:
    try:
        return item[key]
    except KeyError:
        raise FactProcessError(f"nft JSON {what} object is missing {key!r}") from None


class NftablesTable(FactBase[dict[str, Any] | None]):
    """
    Returns the chains and rule comments of a single nftables table, or ``None`` if the
    table doesn't exist. Reading the ruleset requires root, so use ``_sudo=True``.

    ``flags`` lists any table flags (such as ``dormant``) and ``objects`` any named objects
    (such as ``set allowlist``). Each chain lists the comment of every rule in order
    (``None`` for a rule without one). Base chains also include their ``type``, ``hook``,
    numeric ``prio`` and ``policy``. ``chains`` and ``objects`` are empty for a table with
    flags if nft can't print it as JSON (nft 1.0.2 prints invalid JSON for such tables).

    .. code:: python

        {
            "flags": [],
            "objects": [],
            "chains": {
                "input": {
                    "type": "filter",
                    "hook": "input",
                    "prio": -10,
                    "policy": "accept",
                    "rules": ["pyinfra:3f9c0a1b2d4e5f60", None],
                },
                "services": {"rules": []},
            },
        }
    """

    @override
    def requires_command(self, *args: Any, **kwargs: Any) -> str:
        return "nft"

    @override
    def command(self, family: str, table: str) -> StringCommand:
        validate_nftables_table(family, table)
        # Only read the table when the inventory lists it, so a missing table yields no
        # output (``None``) while any other failure, including the scoped reads, fails.
        # Flags come from the text listing (always on its second line), because the JSON
        # flags of older nft versions are unreliable.
        return StringCommand(
            "tables=$(nft list tables) && if printf '%s\\n' \"$tables\" | grep -qxF",
            QuoteString(f"table {family} {table}"),
            "; then listing=$(nft list table",
            QuoteString(family),
            QuoteString(table),
            ") && printf '%s\\n' \"$listing\" | sed -n '2s/^[[:space:]]*flags /flags /p'",
            "&& nft -j list table",
            QuoteString(family),
            QuoteString(table),
            "; fi",
        )

    @override
    def process(self, output: list[str]) -> dict[str, Any] | None:
        flags: list[str] = []
        if output and output[0].startswith("flags "):
            flags = sorted(re.split(r"[,\s]+", output[0][len("flags ") :].strip()))
            output = output[1:]

        text = "".join(output).strip()
        if not text:
            if flags:
                raise FactProcessError("nft printed table flags but no JSON")
            return None

        try:
            data = json.loads(text)
        except ValueError as e:
            if flags:
                return {"flags": flags, "objects": [], "chains": {}}
            raise FactProcessError(f"parse nft JSON output: {e}") from e

        if not isinstance(data, dict) or not isinstance(data.get("nftables"), list):
            raise FactProcessError("decode nft JSON output: missing nftables list")

        chains: dict[str, dict[str, Any]] = {}
        rules: list[dict[str, Any]] = []
        objects: list[str] = []
        seen: set[str] = set()

        for item in data["nftables"]:
            if not isinstance(item, dict) or len(item) != 1:
                raise FactProcessError(f"decode nft JSON output: unexpected object {item!r}")
            kind, value = next(iter(item.items()))
            if not isinstance(value, dict):
                raise FactProcessError(f"decode nft JSON output: unexpected {kind} {value!r}")
            seen.add(kind)
            if kind == "metainfo":
                if value.get("json_schema_version") != 1:
                    raise FactProcessError(
                        f"unsupported nft JSON schema version: {value.get('json_schema_version')!r}"
                    )
            elif kind == "table":
                pass
            elif kind == "chain":
                name = _require(value, "name", "chain")
                chain: dict[str, Any] = {}
                if "hook" in value:
                    chain["type"] = _require(value, "type", "chain")
                    chain["hook"] = value["hook"]
                    chain["prio"] = _require(value, "prio", "chain")
                    chain["policy"] = value.get("policy", "accept")
                chains[name] = chain
            elif kind == "rule":
                rules.append(value)
            else:
                # Sets, maps, flowtables, counters, quotas, ...
                objects.append(f"{kind} {value.get('name')}")

        for required in ("metainfo", "table"):
            if required not in seen:
                raise FactProcessError(f"decode nft JSON output: no {required} object")

        for chain in chains.values():
            chain["rules"] = []

        # Older nft versions interleave rules with chains, so attach them afterwards
        for rule in rules:
            chain_name = _require(rule, "chain", "rule")
            if chain_name not in chains:
                raise FactProcessError(f"nft rule references unknown chain {chain_name!r}")
            chains[chain_name]["rules"].append(rule.get("comment"))

        return {"flags": flags, "objects": sorted(objects), "chains": chains}
