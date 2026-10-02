# SPDX-License-Identifier: LGPL-2.1-only
"""Sigma correlation rules to libsigma ``rules.corr.json``.

``event_count``, ``value_count``, ``temporal``, ``temporal_ordered``, and the
numeric aggregations are multi-event rules. They are not boolean selections,
so they are not written into the ``.sigmac`` artifact. libsigma loads this
JSON in the correlator (``corr_format.h``, ``{"version": 1}``).

A correlation names its base rules by Sigma ``name``. The matcher reports a
hit by the compiled numeric ``rid``. This module records that join. A
correlation whose base rule did not compile is returned as a drop record
with a reason.

Beaconing (``cv_permille``, ``n_buckets``) and SEP #198 string temporal
conditions are not accepted by pySigma's correlation parser. The compiler
peels those documents out of the YAML before ``SigmaCollection.from_yaml``
and passes the dicts to :func:`extract_beaconing_from_dict` and
:func:`extract_temporal_cond_from_dict`.

Each emitted correlation carries: ``id``/``title``, ``type``, the resolved
``base_rule_ids`` (+ the human ``base_rule_names``), ``group_by`` fields,
``timespan_s``, the threshold ``condition`` (op + count, and ``field`` for
``value_count``), the ordered base-rule sequence (``temporal_ordered``), the
primary MITRE technique, and the Sigma ``level``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field as _dc_field
from typing import Optional

from .pipeline import (
    corr_field_to_ecs,
    rule_taxonomy,
    normalize_taxonomy,
    SUPPORTED_TAXONOMIES,
)


def _reject_unknown(names, field_ok) -> list[str]:
    """Names ``field_ok`` refuses. ``field_ok is None`` accepts every name."""
    if field_ok is None:
        return []
    return sorted({n for n in names if n and not field_ok(n)})

try:  # correlation rules live in a submodule whose path has moved across versions
    from sigma.correlations import SigmaCorrelationRule, SigmaCorrelationType
except Exception:  # pragma: no cover - optional dependency
    SigmaCorrelationRule = ()  # isinstance(x, ()) is always False
    SigmaCorrelationType = None


# SigmaHQ's eight correlation types plus the vendor beaconing extension.
# value_sum/avg/percentile/median emit into rules.corr.json; the C engine
# evaluates them. Beaconing is parsed from raw YAML (pySigma rejects cv_permille).
SUPPORTED_TYPES = frozenset({
    "event_count", "value_count", "temporal", "temporal_ordered",
    "value_sum", "value_avg", "value_percentile", "value_median",
    "beaconing",
})
_AGG_TYPES = frozenset({
    "event_count", "value_count", "beaconing",
    "value_sum", "value_avg", "value_percentile", "value_median",
})
_NUMERIC_FIELD_TYPES = frozenset({
    "value_count", "value_sum", "value_avg", "value_percentile", "value_median",
})

# Map pySigma's correlation condition operator enum names to a stable string.
_COND_OPS = {"LT": "lt", "LTE": "lte", "GT": "gt", "GTE": "gte", "EQ": "eq"}


def _aliases_by_canonical(src) -> dict[str, dict[str, str]]:
    """canonical group-by name -> {base-rule name: field on that rule's events}.

    Accepts pySigma ``SigmaCorrelationFieldAliases`` or the raw YAML dict.
    """
    if src is None:
        return {}
    aliases = getattr(src, "aliases", src)
    if not isinstance(aliases, dict) or not aliases:
        return {}
    out: dict[str, dict[str, str]] = {}
    for canonical, adef in aliases.items():
        mapping = getattr(adef, "mapping", adef)
        if not isinstance(mapping, dict):
            continue
        row: dict[str, str] = {}
        for ref, fname in mapping.items():
            name = getattr(ref, "reference", None) or str(ref)
            row[str(name)] = str(fname)
        if row:
            out[str(canonical)] = row
    return out


def _group_by_with_aliases(
    canonical: list[str], refs: list[str], aliases_src,
    *, map_fields: bool = True,
) -> tuple[list[str], Optional[list]]:
    """ECS-mapped group_by plus optional per-base-rule alias rows.

    ``map_fields=False`` (taxonomy: ecs) leaves names as written so a Sigma
    spelling cannot silently remap.
    """
    aliases = _aliases_by_canonical(aliases_src)
    group_by = [corr_field_to_ecs(g, map_fields=map_fields) for g in canonical]
    if not aliases or not refs:
        return group_by, None
    rows: list[list[str]] = []
    any_diff = False
    for ref in refs:
        row = [
            corr_field_to_ecs(
                aliases.get(g, {}).get(ref, g), map_fields=map_fields,
            )
            for g in canonical
        ]
        rows.append(row)
        if row != group_by:
            any_diff = True
    return group_by, (rows if any_diff else None)


@dataclass
class CorrelationRule:
    """A compiled, warm-path-consumable correlation rule (one JSON object)."""

    id: str                      # Sigma name (or uuid), stable node identity
    title: str
    type: str                    # one of SUPPORTED_TYPES
    base_rule_ids: list[int]     # compiled rids this correlation watches
    base_rule_names: list[str]   # the Sigma names (human / debug)
    group_by: list[str]          # ECS field names (post-pipeline)
    timespan_s: int              # window length in seconds
    cond_op: str                 # "gte" | "gt" | "lt" | "lte" | "eq"
    cond_count: int              # threshold N (event_count/value_count)
    # value_count only: the field whose DISTINCT values are counted.
    cond_field: Optional[str] = None
    # temporal_ordered only: the base rids in REQUIRED order (== base_rule_ids,
    # kept explicit so the evaluator does not depend on list ordering surviving).
    ordered_rule_ids: Optional[list[int]] = None
    mitre: Optional[str] = None  # primary MITRE technique (T-id) or None
    level: str = "medium"        # Sigma level, fidelity-tier input
    # beaconing only: max inter-arrival CV tolerance per-mille, and the horizon
    # (0/None = raw ev_ts mode, >0 = bucketed histogram).
    beacon_cv_permille: Optional[int] = None
    beacon_n_buckets: Optional[int] = None
    # SEP #198: postfix boolean over base-rule LOCAL indices. None => all-fired.
    condition_rpn: Optional[list] = None
    # value_percentile: k in P_k (1..100). None => engine default 95.
    value_percentile: Optional[int] = None
    # Per-base-rule group-by field names after |aliases| + ECS map. Parallel
    # to base_rule_ids. None => every base rule uses group_by.
    alias_group_by: Optional[list] = None

    def to_json_obj(self) -> dict:
        obj = {
            "id": self.id,
            "title": self.title,
            "type": self.type,
            "base_rule_ids": self.base_rule_ids,
            "base_rule_names": self.base_rule_names,
            "group_by": self.group_by,
            "timespan_s": self.timespan_s,
            "condition": {"op": self.cond_op, "count": self.cond_count},
            "mitre": self.mitre,
            "level": self.level,
        }
        if self.cond_field is not None:
            obj["condition"]["field"] = self.cond_field
        if self.beacon_cv_permille is not None:
            obj["condition"]["cv_permille"] = self.beacon_cv_permille
        if self.beacon_n_buckets is not None:
            obj["condition"]["n_buckets"] = self.beacon_n_buckets
        if self.ordered_rule_ids is not None:
            obj["ordered_rule_ids"] = self.ordered_rule_ids
        if self.condition_rpn:
            obj["condition_rpn"] = self.condition_rpn
        if self.value_percentile is not None:
            obj["condition"]["percentile"] = self.value_percentile
        if self.alias_group_by:
            obj["alias_group_by"] = self.alias_group_by
        return obj


def _corr_type_name(rule) -> Optional[str]:
    """Normalise the correlation type to a lowercase string, or None."""
    t = getattr(rule, "type", None)
    if t is None:
        return None
    # SigmaCorrelationType enum -> its .name lowercased; tolerate a bare string.
    name = getattr(t, "name", None)
    if name:
        return name.lower()
    return str(t).lower()


def _corr_mitre(rule) -> Optional[str]:
    """Primary MITRE technique of a correlation rule (first ``attack.t*`` tag)."""
    for t in getattr(rule, "tags", []) or []:
        s = str(t)
        if s.startswith("attack.t"):
            return s[len("attack."):].upper()
    return None


def _corr_level(rule) -> str:
    lvl = getattr(rule, "level", None)
    if lvl is None:
        return "medium"
    name = getattr(lvl, "name", None)
    return name.lower() if name else str(lvl).lower()


def extract_correlation(rule, name_to_rid: dict[str, int],
                        name_to_title: "dict[str, str] | None" = None,
                        field_ok=None,
                        ) -> "tuple[Optional[CorrelationRule], Optional[dict]]":
    """Turn one parsed ``SigmaCorrelationRule`` into a ``CorrelationRule``.

    *name_to_rid* maps each successfully-COMPILED base rule's Sigma name to its
    numeric ``rid`` (the join key to ``$!sigma.rules[].id``).

    Returns ``(rule, None)`` on success, or ``(None, drop_record)`` when the
    correlation cannot be supported, an unsupported type, an unparsable
    threshold, or (the landmine case) a referenced base rule that is not present
    in *name_to_rid* (did not compile / not collected by this node).  The
    ``drop_record`` is the dict appended to the compiler's ``dropped[]``.
    """
    title = getattr(rule, "title", "") or ""
    cid = str(getattr(rule, "name", "") or getattr(rule, "id", "") or title)

    def drop(reason: str) -> "tuple[None, dict]":
        return None, {
            "title": title,
            "uuid": str(getattr(rule, "id", "")) or None,
            "correlation_id": cid,
            "reason": reason,
        }

    tax = rule_taxonomy(rule)
    if tax not in SUPPORTED_TAXONOMIES:
        return drop(f"unsupported taxonomy {tax!r} (accepted: sigma, ecs)")
    map_fields = tax == "sigma"

    ctype = _corr_type_name(rule)
    if ctype not in SUPPORTED_TYPES:
        return drop(f"unsupported correlation type '{ctype}' "
                    f"(Gate D supports {sorted(SUPPORTED_TYPES)})")

    # Resolve every referenced base rule to a compiled rid.  A missing one means
    # the correlation can never fire here, NEVER silently dropped.
    refs = [getattr(r, "reference", str(r)) for r in (getattr(rule, "rules", []) or [])]
    if not refs:
        return drop("correlation references no base rule")
    base_ids: list[int] = []
    missing: list[str] = []
    for ref in refs:
        rid = name_to_rid.get(ref)
        if rid is None:
            missing.append(ref)
        else:
            base_ids.append(rid)
    if missing:
        return drop(f"references base rule(s) that did not compile / are not "
                    f"collected by this node: {missing}")

    group_by_raw = [str(g) for g in (getattr(rule, "group_by", None) or [])]
    group_by, alias_group_by = _group_by_with_aliases(
        group_by_raw, refs, getattr(rule, "aliases", None),
        map_fields=map_fields,
    )
    if not map_fields:
        unknown = _reject_unknown(group_by, field_ok)
        if alias_group_by:
            unknown = sorted(set(unknown) | set(
                _reject_unknown((f for row in alias_group_by for f in row), field_ok)
            ))
        if unknown:
            return drop(
                f"taxonomy ecs but unknown ECS group-by {unknown}"
            )

    timespan = getattr(rule, "timespan", None)
    timespan_s = int(getattr(timespan, "seconds", 0) or 0)
    if timespan_s <= 0:
        # temporal/temporal_ordered may omit timespan in some corpora; reject
        # rather than invent an unbounded window (a memory-exhaustion vector).
        return drop("missing or non-positive timespan")

    cond = getattr(rule, "condition", None)
    cond_op = "gte"
    cond_count = 0
    cond_field: Optional[str] = None
    beacon_cv_permille: Optional[int] = None
    beacon_n_buckets: Optional[int] = None
    condition_rpn = None
    value_percentile: Optional[int] = None
    if ctype in _AGG_TYPES:
        if cond is None:
            return drop("count correlation without a condition")
        op_enum = getattr(cond, "op", None)
        op_name = getattr(op_enum, "name", None)
        cond_op = _COND_OPS.get(op_name, "gte") if op_name else "gte"
        cnt = getattr(cond, "count", None)
        if cnt is None:
            return drop("count correlation condition without a count threshold")
        try:
            cond_count = int(cnt)
        except (TypeError, ValueError):
            return drop(f"non-integer count threshold {cnt!r}")
        if cond_count <= 0:
            return drop(f"non-positive count threshold {cond_count}")
        if ctype in _NUMERIC_FIELD_TYPES:
            cond_field = getattr(cond, "fieldref", None) or getattr(cond, "field", None)
            if not cond_field:
                return drop(f"{ctype} without a field (condition.field)")
            cond_field = corr_field_to_ecs(str(cond_field), map_fields=map_fields)
            if not map_fields and _reject_unknown([cond_field], field_ok):
                return drop(
                    f"taxonomy ecs but unknown ECS condition field {cond_field!r}"
                )
        if ctype == "value_percentile":
            pct = getattr(cond, "percentile", None)
            if pct is None:
                value_percentile = 95
            else:
                try:
                    value_percentile = int(pct)
                except (TypeError, ValueError):
                    return drop(f"non-integer percentile {pct!r}")
            if value_percentile < 1 or value_percentile > 100:
                return drop(f"percentile {value_percentile} out of 1..100")
        if ctype == "value_median":
            value_percentile = 50
        if ctype == "beaconing":
            # cond_count is the MIN events in-window; needs >= 3 for a 2-gap CV.
            if cond_count < 3:
                return drop(f"beaconing needs count >= 3 (>= 2 gaps), got {cond_count}")
            cvpm = getattr(cond, "cv_permille", None)
            if cvpm is None:
                return drop("beaconing without condition.cv_permille (CV tolerance)")
            try:
                beacon_cv_permille = int(cvpm)
            except (TypeError, ValueError):
                return drop(f"non-integer cv_permille {cvpm!r}")
            if beacon_cv_permille <= 0:
                return drop(f"non-positive cv_permille {beacon_cv_permille}")
            nbk = getattr(cond, "n_buckets", None)
            if nbk is not None:
                try:
                    beacon_n_buckets = int(nbk)
                except (TypeError, ValueError):
                    return drop(f"non-integer n_buckets {nbk!r}")
                if beacon_n_buckets < 0:
                    return drop(f"negative n_buckets {beacon_n_buckets}")
    else:
        # temporal / temporal_ordered: all referenced base rules must occur
        # (any order / in order) within the window unless a SEP #198 boolean
        # condition over rule names is present.
        cond_op = "gte"
        cond_count = len(base_ids)
        expr = None
        if isinstance(cond, str):
            expr = cond
        elif cond is not None:
            expr = getattr(cond, "expr", None) or getattr(cond, "condition", None)
            if expr is not None and not isinstance(expr, str):
                expr = None
        if expr:
            rpn, err = _cond_rpn_from_expr(expr, refs)
            if err:
                return drop(err)
            condition_rpn = rpn

    ordered_ids = base_ids if ctype == "temporal_ordered" else None

    names = list(refs)
    return CorrelationRule(
        id=cid,
        title=title,
        type=ctype,
        base_rule_ids=base_ids,
        base_rule_names=names,
        group_by=group_by,
        timespan_s=timespan_s,
        cond_op=cond_op,
        cond_count=cond_count,
        cond_field=cond_field,
        ordered_rule_ids=ordered_ids,
        mitre=_corr_mitre(rule),
        level=_corr_level(rule),
        beacon_cv_permille=beacon_cv_permille,
        beacon_n_buckets=beacon_n_buckets,
        condition_rpn=condition_rpn,
        value_percentile=value_percentile,
        alias_group_by=alias_group_by,
    ), None


def _cond_rpn_from_expr(expr: str, refs: list[str]) -> "tuple[list | None, str | None]":
    """Shunting-yard: infix boolean over base-rule names -> postfix token list.

    Tokens: ``and`` / ``or`` / ``not`` / parentheses / rule names from *refs*.
    Output is the C loader's ``condition_rpn`` shape:
    ``{"k":"sel","r":<idx>}`` / ``{"k":"and"|"or"|"not"}``.
    """
    name_to_idx = {n: i for i, n in enumerate(refs)}
    raw = (expr or "").replace("(", " ( ").replace(")", " ) ")
    toks = [t for t in raw.split() if t]
    if not toks:
        return None, "empty temporal condition"
    prec = {"not": 3, "and": 2, "or": 1}
    right_assoc = {"not"}
    out: list = []
    ops: list[str] = []

    def emit_sel(name: str) -> "str | None":
        idx = name_to_idx.get(name)
        if idx is None:
            return f"condition references unknown rule {name!r}"
        out.append({"k": "sel", "r": idx})
        return None

    for t in toks:
        tl = t.lower()
        if tl in ("and", "or", "not"):
            while ops and ops[-1] != "(":
                top = ops[-1]
                if prec[top] > prec[tl] or (prec[top] == prec[tl] and tl not in right_assoc):
                    out.append({"k": ops.pop()})
                else:
                    break
            ops.append(tl)
        elif t == "(":
            ops.append(t)
        elif t == ")":
            while ops and ops[-1] != "(":
                out.append({"k": ops.pop()})
            if not ops:
                return None, "unbalanced parentheses in temporal condition"
            ops.pop()
        else:
            err = emit_sel(t)
            if err:
                return None, err
    while ops:
        if ops[-1] == "(":
            return None, "unbalanced parentheses in temporal condition"
        out.append({"k": ops.pop()})
    return out, None


_TIMESPAN_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def _parse_timespan_str(v) -> int:
    """'1h' / '5m' / '30s' / '2d' or a bare int (seconds) -> seconds; 0 if
    unparseable (the caller drops on <= 0)."""
    if isinstance(v, (int, float)):
        return int(v)
    s = str(v or "").strip().lower()
    if not s:
        return 0
    if s[-1] in _TIMESPAN_UNITS:
        try:
            return int(s[:-1]) * _TIMESPAN_UNITS[s[-1]]
        except ValueError:
            return 0
    try:
        return int(s)
    except ValueError:
        return 0


def extract_beaconing_from_dict(doc: dict, name_to_rid: "dict[str, int]",
                                 field_ok=None):
    """Compile a ``type: beaconing`` correlation straight from its RAW YAML dict,
    bypassing pySigma.

    pySigma's ``SigmaCorrelationCondition`` hard-rejects any condition key it does
    not know (our ``cv_permille`` / ``n_buckets``), so a beaconing rule never
    survives ``SigmaCollection.from_yaml``.  The compiler pulls beaconing files
    out before that parse and hands their dicts here.  Resolution mirrors
    :func:`extract_correlation`: base-rule names -> compiled rids via
    ``name_to_rid``, ``timespan`` -> seconds, ``condition`` -> min-event count +
    the beacon params.  Returns ``(CorrelationRule | None, drop_record | None)``.
    """
    corr = doc.get("correlation") or {}
    cid = str(doc.get("name") or doc.get("id") or doc.get("title") or "beaconing")
    title = str(doc.get("title") or cid)

    def drop(reason):
        return None, {"title": title,
                      "uuid": str(doc.get("id") or "") or None,
                      "reason": reason}

    if str(corr.get("type") or "").lower() != "beaconing":
        return drop("not a beaconing correlation")

    refs = corr.get("rules") or []
    if isinstance(refs, str):
        refs = [refs]
    base_ids: list[int] = []
    for nm in refs:
        rid = name_to_rid.get(str(nm))
        if rid is None:
            return drop(f"beaconing base rule not compiled: {nm!r}")
        base_ids.append(rid)
    if not base_ids:
        return drop("beaconing without a base rule")

    tax = normalize_taxonomy(doc.get("taxonomy"))
    if tax not in SUPPORTED_TAXONOMIES:
        return drop(f"unsupported taxonomy {tax!r} (accepted: sigma, ecs)")
    map_fields = tax == "sigma"

    group_by_raw = corr.get("group-by") or corr.get("group_by") or []
    if isinstance(group_by_raw, str):
        group_by_raw = [group_by_raw]
    group_by_raw = [str(g) for g in group_by_raw]
    group_by, alias_group_by = _group_by_with_aliases(
        group_by_raw, [str(n) for n in refs], corr.get("aliases"),
        map_fields=map_fields,
    )
    if not map_fields:
        unknown = _reject_unknown(group_by, field_ok)
        if unknown:
            return drop(
                f"taxonomy ecs but unknown ECS group-by {unknown}"
            )

    timespan_s = _parse_timespan_str(corr.get("timespan"))
    if timespan_s <= 0:
        return drop("beaconing with missing or non-positive timespan")

    cond = corr.get("condition") or {}
    cond_op = "gte"
    cond_count = None
    for op in ("gte", "gt", "lte", "lt", "eq"):
        if op in cond:
            cond_op, cond_count = op, cond[op]
            break
    if cond_count is None:
        cond_count = cond.get("count")
    try:
        cond_count = int(cond_count)
    except (TypeError, ValueError):
        return drop(f"beaconing non-integer count {cond_count!r}")
    if cond_count < 3:
        return drop(f"beaconing needs count >= 3 (>= 2 gaps), got {cond_count}")

    cvpm = cond.get("cv_permille")
    if cvpm is None:
        return drop("beaconing without condition.cv_permille (CV tolerance)")
    try:
        beacon_cv_permille = int(cvpm)
    except (TypeError, ValueError):
        return drop(f"beaconing non-integer cv_permille {cvpm!r}")
    if beacon_cv_permille <= 0:
        return drop(f"beaconing non-positive cv_permille {beacon_cv_permille}")

    beacon_n_buckets = None
    nbk = cond.get("n_buckets")
    if nbk is not None:
        try:
            beacon_n_buckets = int(nbk)
        except (TypeError, ValueError):
            return drop(f"beaconing non-integer n_buckets {nbk!r}")
        if beacon_n_buckets < 0:
            return drop(f"beaconing negative n_buckets {beacon_n_buckets}")

    mitre = None
    for t in doc.get("tags") or []:
        s = str(t)
        if s.lower().startswith("attack.t"):
            mitre = s[len("attack."):].upper()
            break

    level = str(doc.get("level") or "medium").lower()

    return CorrelationRule(
        id=cid, title=title, type="beaconing",
        base_rule_ids=base_ids, base_rule_names=[str(n) for n in refs],
        group_by=group_by, timespan_s=timespan_s,
        cond_op=cond_op, cond_count=cond_count,
        mitre=mitre, level=level,
        beacon_cv_permille=beacon_cv_permille,
        beacon_n_buckets=beacon_n_buckets,
        alias_group_by=alias_group_by,
    ), None


def extract_temporal_cond_from_dict(doc: dict, name_to_rid: "dict[str, int]"):
    """Compile a temporal / temporal_ordered rule with a SEP #198 string
    ``condition`` from its RAW YAML dict.

    pySigma's correlation condition is a count/op/field object; a boolean
    ``condition: rule_a and rule_b and not rule_c`` does not survive
    ``SigmaCollection.from_yaml``. The compiler pulls those files out (same
    trick as beaconing) and resolves them here.
    """
    corr = doc.get("correlation") or {}
    cid = str(doc.get("name") or doc.get("id") or doc.get("title") or "temporal")
    title = str(doc.get("title") or cid)
    ctype = str(corr.get("type") or "").lower()

    def drop(reason):
        return None, {"title": title,
                      "uuid": str(doc.get("id") or "") or None,
                      "correlation_id": cid,
                      "reason": reason}

    if ctype not in ("temporal", "temporal_ordered"):
        return drop("not a temporal correlation")
    expr = corr.get("condition")
    if not isinstance(expr, str) or not expr.strip():
        return drop("temporal condition is not a boolean expression")

    refs = corr.get("rules") or []
    if isinstance(refs, str):
        refs = [refs]
    refs = [str(n) for n in refs]
    base_ids: list[int] = []
    for nm in refs:
        rid = name_to_rid.get(nm)
        if rid is None:
            return drop(f"temporal base rule not compiled: {nm!r}")
        base_ids.append(rid)
    if not base_ids:
        return drop("temporal without a base rule")

    rpn, err = _cond_rpn_from_expr(expr, refs)
    if err:
        return drop(err)

    group_by_raw = corr.get("group-by") or corr.get("group_by") or []
    if isinstance(group_by_raw, str):
        group_by_raw = [group_by_raw]
    group_by_raw = [str(g) for g in group_by_raw]
    group_by, alias_group_by = _group_by_with_aliases(
        group_by_raw, refs, corr.get("aliases"),
    )
    timespan_s = _parse_timespan_str(corr.get("timespan"))
    if timespan_s <= 0:
        return drop("temporal with missing or non-positive timespan")

    mitre = None
    for t in doc.get("tags") or []:
        s = str(t)
        if s.lower().startswith("attack.t"):
            mitre = s[len("attack."):].upper()
            break
    level = str(doc.get("level") or "medium").lower()
    ordered = list(base_ids) if ctype == "temporal_ordered" else None
    return CorrelationRule(
        id=cid, title=title, type=ctype,
        base_rule_ids=base_ids, base_rule_names=refs,
        group_by=group_by, timespan_s=timespan_s,
        cond_op="gte", cond_count=len(base_ids),
        ordered_rule_ids=ordered,
        mitre=mitre, level=level,
        condition_rpn=rpn,
        alias_group_by=alias_group_by,
    ), None


def correlations_to_json(correlations: "list[CorrelationRule]") -> str:
    """Serialise compiled correlations to the sibling-artifact JSON string."""
    return json.dumps(
        {"version": 1, "correlations": [c.to_json_obj() for c in correlations]},
        indent=2, sort_keys=False,
    )


def load_correlations(blob: "str | bytes") -> "list[dict]":
    """Parse a ``rules.corr.json`` artifact into a list of correlation dicts.

    Tolerant: accepts either the wrapped ``{"correlations": [...]}`` object or a
    bare list.  Returns ``[]`` for empty/invalid input (the warm evaluator then
    simply runs no correlations, no crash on a missing artifact).
    """
    if isinstance(blob, bytes):
        blob = blob.decode("utf-8")
    try:
        data = json.loads(blob)
    except (json.JSONDecodeError, TypeError, ValueError):
        return []
    if isinstance(data, dict):
        corr = data.get("correlations")
        return corr if isinstance(corr, list) else []
    if isinstance(data, list):
        return data
    return []
