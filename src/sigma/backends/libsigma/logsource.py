# SPDX-License-Identifier: LGPL-2.1-only
"""Sigma logsource tokens to libsigma bucket keys.

libsigma buckets a rule by ``event.category`` and by the raw product and
service tokens. This map says which ECS ``event.category`` a Sigma category
or service corresponds to (``process_creation`` -> ``process``). A logsource
with no row is still indexed under its own token, so the matcher can select
it when the event carries that token. The map does not drop rules.
"""

from __future__ import annotations

# Sigma logsource (category | service | product) -> ECS `event.category`, the
# matcher bucket key.  The VALUE side MUST be the exact `event.category` string
# our rulebases emit on parsed events (web/network/dns/authentication/email/
# process/...), because the matcher buckets events by their literal
# `event.category`; a key mismatch would silently prune a rule (a MISSED
# DETECTION).  A logsource absent here -> always-verify (never pruned).
_LOGSOURCE_CATEGORY: dict[str, str] = {
    # web / proxy
    "webserver": "web",
    "proxy": "web",
    # network
    "firewall": "network",
    "network_connection": "network",
    "zeek": "network",
    # dns
    "dns": "dns",
    "dns_query": "dns",
    # IDS/IPS alerts are bucketed under ECS event.category intrusion_detection.
    # Field names on those rules are usually already ECS, so the rename
    # pipeline has no ids row.
    "ids": "intrusion_detection",
    # authentication / linux host auth
    "authentication": "authentication",
    "sshd": "authentication",
    "auth": "authentication",
    "sudo": "authentication",
    "login": "authentication",
    "pam": "authentication",
    # mail / smtp
    "smtp": "email",
    "mail": "email",
    # endpoint process telemetry
    "process_creation": "process",
    "process_access": "process",
    "ps_script": "process",
    "ps_module": "process",
}

ALWAYS_VERIFY = ""


def bucket_keys_for_logsource(
    category: str | None,
    service: str | None,
    product: str | None,
) -> list[str]:
    """Matcher bucket keys for a Sigma logsource.

    Every logsource token is a key. The matcher evaluates the UNION of
    buckets whose keys appear on the event (``event.category``,
    ``techno``, ``product``, plus the older ECS aliases). A rule with
    ``product: nginx`` therefore lives in the ``nginx`` bucket: an event
    that does not carry ``product=nginx`` does not run it.

    ``category`` / ``service`` tokens that the vocabulary maps also add
    the ECS ``event.category`` key (``process_creation`` -> ``process``).
    Empty logsource -> always-verify key ``""``.
    """
    keys: list[str] = []
    seen: set[str] = set()

    def add(key: str) -> None:
        if key not in seen:
            seen.add(key)
            keys.append(key)

    for tok in (category, service, product):
        if tok is None:
            continue
        cat = _LOGSOURCE_CATEGORY.get(tok)
        if cat is not None:
            add(cat)
        if tok != cat:
            add(str(tok))
    return keys if keys else [ALWAYS_VERIFY]


def sigma_category_tokens_for_ecs(ecs_categories: "set[str]") -> "set[str]":
    """Sigma logsource tokens that map to the given ECS ``event.category`` values.
    That set is ``collected_categories`` for the compiler's per-node gate.

    Inverts :data:`_LOGSOURCE_CATEGORY`.  The result is compared ONLY against a
    rule's ``logsource.category`` (the ``product`` dimension is data-driven from
    source platform declarations, the ``service`` dimension stays lenient).
    Empty input -> empty set (caller treats that as fail-open on the category
    dimension: no narrowing).
    """
    if not ecs_categories:
        return set()
    return {
        tok for tok, ecs in _LOGSOURCE_CATEGORY.items() if ecs in ecs_categories
    }
